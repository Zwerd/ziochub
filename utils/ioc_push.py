"""
Push newly created IOCs to configurable HTTP endpoints (JSON body from Jinja2 template).

Admin: Settings → IOC push. Each target: URL, auth (none / Basic / API key), body template
with variables under `ioc` (type, value, analyst, ticket_id, comment, etc.).

Runs in a background thread (like YARA push) so submission APIs stay responsive.
Skips when analyst matches misp_sync_user (same loop-avoidance as MISP push).
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
import urllib.error
import urllib.request
import ssl
from datetime import datetime
from typing import Any, Callable, Optional

from jinja2.sandbox import SandboxedEnvironment
from models import _utcnow
from jinja2.exceptions import SecurityError, TemplateError

logger = logging.getLogger(__name__)

MAX_BODY_TEMPLATE_CHARS = 32768
DEFAULT_CONTENT_TYPE = 'application/json'
# Per requirement: a 30s timeout is considered a failure and must be reported.
REQUEST_TIMEOUT_SEC = 30


def _get_setting(key: str, default: str = '') -> str:
    import app as _app
    return _app._get_setting(key, default)


def _ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if verify_ssl:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _make_jinja_env() -> SandboxedEnvironment:
    env = SandboxedEnvironment(autoescape=False)

    def _tojson_filter(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    env.filters['tojson'] = _tojson_filter
    return env


_jinja_env = _make_jinja_env()


def ioc_context_from_submission(
    *,
    ioc_type: str,
    value: str,
    analyst: str,
    ticket_id: Optional[str] = None,
    comment: Optional[str] = None,
    expiration_date: Optional[datetime] = None,
    campaign_id: Optional[int] = None,
    tags_json: Optional[str] = None,
    submission_method: str = 'single',
    user_id: Optional[int] = None,
    created_at: Optional[datetime] = None,
    action: str = 'create',
    remove_reason: str = '',
) -> dict[str, Any]:
    """Build the dict passed to Jinja as `ioc` (also returned as top-level for helpers)."""
    tags_list: list[str] = []
    raw_tags = (tags_json or '').strip() or '[]'
    try:
        parsed = json.loads(raw_tags)
        if isinstance(parsed, list):
            tags_list = [str(x) for x in parsed if x is not None]
    except (TypeError, ValueError):
        tags_list = []
    exp_s = ''
    if expiration_date is not None and hasattr(expiration_date, 'isoformat'):
        try:
            exp_s = expiration_date.isoformat()
        except Exception:
            exp_s = str(expiration_date)[:32]
    created = created_at or _utcnow()
    created_s = created.isoformat() if hasattr(created, 'isoformat') else str(created)

    return {
        'action': (action or '').strip() or 'create',
        'remove_reason': (remove_reason or '').strip(),
        'type': (ioc_type or '').strip(),
        'value': (value or '').strip(),
        'analyst': (analyst or '').strip().lower(),
        'ticket_id': (ticket_id or '').strip(),
        'comment': (comment or '').strip() if comment else '',
        'expiration_date': exp_s,
        'campaign_id': campaign_id,
        'tags': tags_list,
        'tags_json': raw_tags,
        'submission_method': (submission_method or '').strip() or 'single',
        'user_id': user_id,
        'created_at': created_s,
    }


def render_body_template(template_str: str, ioc: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """
    Render Jinja template with context { ioc: ... }.
    Returns (rendered_str, error_message). error_message set on failure.
    """
    if not template_str or not template_str.strip():
        return None, 'Empty body template'
    if len(template_str) > MAX_BODY_TEMPLATE_CHARS:
        return None, f'Body template exceeds {MAX_BODY_TEMPLATE_CHARS} characters'
    try:
        tpl = _jinja_env.from_string(template_str)
        out = tpl.render(ioc=ioc)
        return out, None
    except SecurityError as e:
        logger.warning('IOC push template security error: %s', e)
        return None, f'Template blocked: {e}'
    except TemplateError as e:
        logger.warning('IOC push template error: %s', e)
        return None, f'Template error: {e}'
    except Exception as e:
        logger.exception('IOC push template render failed')
        return None, str(e)


def _validate_json_body(body: str, content_type: str) -> Optional[str]:
    ct = (content_type or DEFAULT_CONTENT_TYPE).lower()
    if 'json' not in ct:
        return None
    try:
        json.loads(body)
    except (TypeError, ValueError) as e:
        return f'Body is not valid JSON for Content-Type {content_type}: {e}'
    return None


def _post_target(
    target: dict[str, Any],
    body_bytes: bytes,
    content_type: str,
    *,
    verify_ssl: bool,
    audit_log_fn: Callable[..., None],
) -> tuple[bool, str]:
    url = (target.get('url') or '').strip()
    name = (target.get('name') or '').strip() or 'Target'
    method = (target.get('method') or 'POST').strip().upper() or 'POST'
    if method != 'POST':
        return False, f'Unsupported method {method} (only POST supported)'
    if not url:
        return False, 'Missing URL'

    ctx = _ssl_context(verify_ssl)
    req = urllib.request.Request(url, data=body_bytes, method='POST')
    req.add_header('Content-Type', content_type or DEFAULT_CONTENT_TYPE)

    auth_type = (target.get('auth_type') or 'none').strip().lower()
    if auth_type == 'basic':
        u = (target.get('username') or '').strip()
        p = (target.get('password') or '').strip()
        if u or p:
            token = base64.b64encode(f'{u}:{p}'.encode('utf-8')).decode('ascii')
            req.add_header('Authorization', f'Basic {token}')
    elif auth_type == 'api_key':
        key = (target.get('api_key') or '').strip()
        if key:
            hname = (target.get('api_key_header') or 'X-API-Key').strip() or 'X-API-Key'
            req.add_header(hname, key)

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC, context=ctx) as resp:
            code = resp.getcode()
            if 200 <= code < 300:
                audit_log_fn('ioc_push_ok', f'target={name} code={code}')
                return True, f'HTTP {code}'
            audit_log_fn('ioc_push_fail', f'target={name} code={code}')
            return False, f'HTTP {code}'
    except urllib.error.HTTPError as e:
        audit_log_fn('ioc_push_fail', f'target={name} code={e.code}')
        return False, f'HTTP {e.code} {e.reason}'
    except urllib.error.URLError as e:
        audit_log_fn('ioc_push_fail', f'target={name} error={e.reason}')
        return False, str(e.reason or e)
    except Exception as e:
        logger.exception('ioc_push POST failed for %s', name)
        audit_log_fn('ioc_push_fail', f'target={name} error={e}')
        return False, str(e)


def load_targets() -> list[dict[str, Any]]:
    raw = (_get_setting('ioc_push_targets', '[]') or '').strip() or '[]'
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (TypeError, ValueError):
        return []


def push_one_ioc_to_all_targets(
    ioc: dict[str, Any],
    *,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> dict[str, Any]:
    """
    Push a single IOC (context dict) to all enabled targets. Synchronous.
    Returns { 'overall_success': bool, 'results': [ { name, url, success, message } ] }.
    """
    if not audit_log_fn:
        def audit_log_fn(*_a, **_k):
            pass

    if (_get_setting('ioc_push_enabled', 'false') or '').strip().lower() not in ('true', '1', 'yes'):
        return {'overall_success': True, 'results': [], 'skipped': True}

    global_insecure = (_get_setting('ioc_push_ignore_ssl', 'false') or '').strip().lower() in ('true', '1', 'yes')
    if global_insecure:
        logger.warning('IOC push: TLS certificate verification disabled globally (ioc_push_ignore_ssl)')

    targets = load_targets()
    results = []
    any_ok = False
    any_attempt = False

    for t in targets:
        if not isinstance(t, dict):
            continue
        if not t.get('enabled', True):
            continue
        name = (t.get('name') or '').strip() or 'Target'
        url = (t.get('url') or '').strip()
        tmpl = (t.get('body_template') or '').strip()
        if not tmpl:
            results.append({'name': name, 'url': url, 'success': False, 'message': 'Missing body_template'})
            audit_log_fn('ioc_push_skip', f'target={name} reason=no_template')
            continue

        rendered, err = render_body_template(tmpl, ioc)
        if err:
            results.append({'name': name, 'url': url, 'success': False, 'message': err})
            audit_log_fn('ioc_push_fail', f'target={name} reason=template')
            continue

        ct = (t.get('content_type') or DEFAULT_CONTENT_TYPE).strip() or DEFAULT_CONTENT_TYPE
        json_err = _validate_json_body(rendered, ct)
        if json_err:
            results.append({'name': name, 'url': url, 'success': False, 'message': json_err})
            audit_log_fn('ioc_push_fail', f'target={name} reason=invalid_json')
            continue

        per_verify = t.get('verify_ssl')
        if per_verify is None:
            verify_ssl = not global_insecure
        else:
            verify_ssl = str(per_verify).lower() in ('true', '1', 'yes')
        if not verify_ssl:
            logger.warning('IOC push target %s: TLS verification off', name)

        body_bytes = rendered.encode('utf-8')
        any_attempt = True
        ok, msg = _post_target(t, body_bytes, ct, verify_ssl=verify_ssl, audit_log_fn=audit_log_fn)
        results.append({'name': name, 'url': url, 'success': ok, 'message': msg})
        if ok:
            any_ok = True

    overall = (not any_attempt) or any_ok
    return {'overall_success': overall, 'results': results}


def push_one_ioc_to_targets(
    ioc: dict[str, Any],
    targets: list[dict[str, Any]],
    *,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> dict[str, Any]:
    """
    Push a single IOC context to a specific list of targets (subset).
    Same behavior as push_one_ioc_to_all_targets, but caller controls the target list.
    """
    if not audit_log_fn:
        def audit_log_fn(*_a, **_k):
            pass
    global_insecure = (_get_setting('ioc_push_ignore_ssl', 'false') or '').strip().lower() in ('true', '1', 'yes')
    results = []
    any_ok = False
    any_attempt = False
    for t in targets or []:
        if not isinstance(t, dict):
            continue
        if not t.get('enabled', True):
            continue
        name = (t.get('name') or '').strip() or 'Target'
        url = (t.get('url') or '').strip()
        tmpl = (t.get('body_template') or '').strip()
        if not tmpl:
            results.append({'name': name, 'url': url, 'success': False, 'message': 'Missing body_template'})
            continue
        rendered, err = render_body_template(tmpl, ioc)
        if err:
            results.append({'name': name, 'url': url, 'success': False, 'message': err})
            continue
        ct = (t.get('content_type') or DEFAULT_CONTENT_TYPE).strip() or DEFAULT_CONTENT_TYPE
        json_err = _validate_json_body(rendered, ct)
        if json_err:
            results.append({'name': name, 'url': url, 'success': False, 'message': json_err})
            continue
        per_verify = t.get('verify_ssl')
        if per_verify is None:
            verify_ssl = not global_insecure
        else:
            verify_ssl = str(per_verify).lower() in ('true', '1', 'yes')
        any_attempt = True
        ok, msg = _post_target(t, rendered.encode('utf-8'), ct, verify_ssl=verify_ssl, audit_log_fn=audit_log_fn)
        results.append({'name': name, 'url': url, 'success': ok, 'message': msg})
        if ok:
            any_ok = True
    overall = (not any_attempt) or any_ok
    return {'overall_success': overall, 'results': results}


def schedule_ioc_push_after_create(app, ioc_context: dict[str, Any]) -> None:
    """If enabled and not skipped, run push in a daemon thread (one IOC)."""
    schedule_ioc_push_batch(app, [ioc_context])


def schedule_ioc_push_batch(app, contexts: list[dict[str, Any]], *, delay_sec: float = 0.05) -> None:
    """
    Run IOC push for each context in a single background thread (sequential, light throttle).
    """
    if not contexts:
        return
    if (_get_setting('ioc_push_enabled', 'false') or '').strip().lower() not in ('true', '1', 'yes'):
        return

    misp_sync = (_get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip().lower()
    filtered = []
    for c in contexts:
        if not isinstance(c, dict):
            continue
        if (c.get('analyst') or '').strip().lower() == misp_sync:
            continue
        filtered.append(c)

    if not filtered:
        return

    targets = load_targets()
    if not any(isinstance(t, dict) and t.get('enabled', True) and (t.get('body_template') or '').strip() for t in targets):
        return

    try:
        app_obj = app._get_current_object()
    except Exception:
        app_obj = app

    def _worker():
        import app as _app
        audit = _app.audit_log
        with app_obj.app_context():
            for ctx in filtered:
                try:
                    res = push_one_ioc_to_all_targets(ctx, audit_log_fn=audit)
                    try:
                        from utils.integration_telemetry import record_ioc_push_results
                        action = (ctx.get('action') or 'create') if isinstance(ctx, dict) else 'create'
                        rr = (ctx.get('remove_reason') or '') if isinstance(ctx, dict) else ''
                        action_l = str(action).strip().lower()
                        rr_l = str(rr).strip().lower()
                        if action_l in ('remove', 'delete', 'revoke') and rr_l in ('expired', 'expire'):
                            kind = 'expire'
                        elif action_l in ('remove', 'delete', 'revoke') and rr_l in ('manual_delete', 'manual', 'deleted'):
                            kind = 'manual_remove'
                        elif action_l == 'expire_remove':
                            kind = 'expire'
                        elif action_l == 'delete_remove':
                            kind = 'manual_remove'
                        else:
                            kind = 'create'
                        record_ioc_push_results(res, kind=kind, context=ctx if isinstance(ctx, dict) else None)
                    except Exception:
                        pass
                except Exception:
                    logger.exception('IOC push batch item failed')
                if delay_sec > 0:
                    time.sleep(delay_sec)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def test_ioc_push_targets(
    targets: list[dict[str, Any]],
    *,
    verify_ssl_override: Optional[bool] = None,
    sample_ioc: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    POST sample (or default) IOC context to each target in the list-same rendering/POST as live push.
    Used by Admin Test without requiring save.
    """
    ioc = sample_ioc or ioc_context_from_submission(
        ioc_type='Domain',
        value='example.com',
        analyst='ziochub_test',
        ticket_id='TEST-1',
        comment='ZIoCHub IOC push connectivity test',
        submission_method='single',
        user_id=None,
    )

    def noop(*_a, **_k):
        pass

    global_insecure = (_get_setting('ioc_push_ignore_ssl', 'false') or '').strip().lower() in ('true', '1', 'yes')
    results = []
    any_ok = False

    for t in targets or []:
        if not isinstance(t, dict):
            continue
        name = (t.get('name') or '').strip() or 'Target'
        tmpl = (t.get('body_template') or '').strip()
        if not tmpl:
            results.append({'name': name, 'success': False, 'message': 'Missing body_template'})
            continue
        rendered, err = render_body_template(tmpl, ioc)
        if err:
            results.append({'name': name, 'success': False, 'message': err})
            continue
        ct = (t.get('content_type') or DEFAULT_CONTENT_TYPE).strip() or DEFAULT_CONTENT_TYPE
        json_err = _validate_json_body(rendered, ct)
        if json_err:
            results.append({'name': name, 'success': False, 'message': json_err})
            continue
        if verify_ssl_override is not None:
            verify_ssl = verify_ssl_override
        else:
            per_verify = t.get('verify_ssl')
            if per_verify is None:
                verify_ssl = not global_insecure
            else:
                verify_ssl = str(per_verify).lower() in ('true', '1', 'yes')
        ok, msg = _post_target(t, rendered.encode('utf-8'), ct, verify_ssl=verify_ssl, audit_log_fn=noop)
        results.append({'name': name, 'success': ok, 'message': msg})
        if ok:
            any_ok = True

    return {
        'overall_success': any_ok or not results,
        'results': results,
    }
