"""
``utils.cisco_esa`` — Cisco Secure Email Gateway (ESA / AsyncOS) dictionary sync via REST API.

Auth: POST {base}/login (Base64 userName + passphrase), then ``jwttoken`` header on API calls.

Paths (v2.0, Cisco Secure Email API Guide): POST/DELETE
``config/dictionaries/<dictionary_name>/words?device_type=esa`` (cluster adds ``&mode=cluster``, etc.).

- **POST add:** ``{"data":{"words":[["term1"],["term2"],...]}}``-each term is a list (optional weight/prefix).
- **DELETE:** ``{"data":{"words":["term1","term2",...]}}``-flat string array (per Cisco docs; not nested lists).

Multiple IOCs per dictionary are batched into one request after a single login.

Mappings (system_settings ``esa_mappings``): JSON array of
``{"dictionary_name": "<as on ESA>", "ioc_type": "Email"|"Domain"|"IP"|"URL"}``-one IOC type per row.

Used after IOC create (background), on manual revoke, and from cleaner.py before deleting expired rows.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import ssl
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any, Callable, Optional
from urllib.parse import quote

from utils.http_identity import apply_user_agent_to_request

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SEC = 45

ESA_IOC_TYPES: tuple[str, ...] = ('Email', 'Domain', 'IP', 'URL')

ESA_DEPLOYMENT_MODES: tuple[str, ...] = ('standalone', 'cluster', 'group', 'machine')


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


def esa_settings_dict() -> dict[str, str]:
    """Return relevant system_settings keys (for SQLite cleaner without Flask)."""
    keys = (
        'esa_enabled', 'esa_base_url', 'esa_username', 'esa_passphrase', 'esa_verify_ssl',
        'esa_skip_misp_sync', 'esa_mappings',
        'esa_deployment_mode', 'esa_group_name', 'esa_host_name',
    )
    return {k: _get_setting(k, '') for k in keys}


_ESA_SQLITE_DEFAULTS: dict[str, str] = {
    'esa_enabled': 'false',
    'esa_base_url': '',
    'esa_username': '',
    'esa_passphrase': '',
    'esa_verify_ssl': 'true',
    'esa_skip_misp_sync': 'true',
    'esa_cleanup_on_expire': 'true',
    'esa_mappings': '[]',
    'esa_deployment_mode': 'standalone',
    'esa_group_name': '',
    'esa_host_name': '',
}


def esa_settings_from_sqlite_rows(rows: list[tuple[str, str]]) -> dict[str, str]:
    """Build settings dict from sqlite (key, value) rows for cleaner (no Flask app)."""
    m = dict(_ESA_SQLITE_DEFAULTS)
    for k, v in rows:
        if isinstance(k, str) and k.startswith('esa_'):
            m[k] = v if v is not None else ''
    return m


def normalize_dictionary_word(ioc_type: str, value: str) -> str:
    """Normalize IOC value for dictionary storage (consistent add/remove)."""
    v = (value or '').strip()
    if not v:
        return v
    t = (ioc_type or '').strip()
    if t in ('Email', 'Domain', 'URL', 'Hash'):
        return v.lower()
    return v


def canonical_esa_ioc_type(raw: Any) -> Optional[str]:
    """Map user/API input to Email | Domain | IP | URL, or None if not supported for ESA."""
    s = str(raw or '').strip()
    if not s:
        return None
    u = s.upper()
    aliases = {'EMAIL': 'Email', 'DOMAIN': 'Domain', 'IP': 'IP', 'URL': 'URL'}
    if u in aliases:
        return aliases[u]
    if s in ESA_IOC_TYPES:
        return s
    return None


def parse_mappings(raw: str) -> list[dict[str, Any]]:
    """
    Return rows: {dictionary_name, ioc_type} with ioc_type in ESA_IOC_TYPES.
    Accepts new format (ioc_type) or legacy (ioc_types array); legacy rows expand to one entry per type.
    """
    allowed = frozenset(ESA_IOC_TYPES)
    try:
        data = json.loads((raw or '').strip() or '[]')
        if not isinstance(data, list):
            return []
        out: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            name = (item.get('dictionary_name') or item.get('name') or '').strip()
            if not name:
                continue
            single = canonical_esa_ioc_type(item.get('ioc_type'))
            if single and single in allowed:
                out.append({'dictionary_name': name, 'ioc_type': single})
                continue
            types_raw = item.get('ioc_types') or item.get('types') or []
            if isinstance(types_raw, list):
                for x in types_raw:
                    ct = canonical_esa_ioc_type(x)
                    if ct and ct in allowed:
                        out.append({'dictionary_name': name, 'ioc_type': ct})
        return out
    except (TypeError, ValueError):
        return []


def dictionary_names_for_ioc_type(mappings: list[dict[str, Any]], ioc_type: str) -> list[str]:
    t = (ioc_type or '').strip()
    names: list[str] = []
    for m in mappings:
        if m.get('ioc_type') == t:
            names.append(m['dictionary_name'])
    return names


def _base_url_normalize(url: str) -> str:
    u = (url or '').strip().rstrip('/')
    return u


def esa_login(base_url: str, username: str, passphrase: str, verify_ssl: bool) -> tuple[Optional[str], str]:
    """
    POST /login with Base64 credentials. Returns (jwt_token, error_message).
    """
    base = _base_url_normalize(base_url)
    if not base:
        return None, 'esa_base_url is empty'
    u = (username or '').strip()
    p = (passphrase or '').strip()
    if not u or not p:
        return None, 'esa_username or esa_passphrase is empty'
    try:
        u_b = base64.b64encode(u.encode('utf-8')).decode('ascii')
        p_b = base64.b64encode(p.encode('utf-8')).decode('ascii')
    except Exception as e:
        return None, f'Base64 encode failed: {e}'
    body = json.dumps({'data': {'userName': u_b, 'passphrase': p_b}})
    url = f'{base}/login'
    ctx = _ssl_context(verify_ssl)
    req = urllib.request.Request(url, data=body.encode('utf-8'), method='POST')
    apply_user_agent_to_request(req)
    req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC, context=ctx) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode('utf-8', errors='replace')
        except Exception:
            raw = ''
        return None, f'HTTP {e.code}: {raw[:500]}'
    except urllib.error.URLError as e:
        return None, str(e.reason or e)
    except Exception as e:
        return None, str(e)

    if code not in (200, 201):
        return None, f'HTTP {code}: {raw[:500]}'

    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return None, f'Non-JSON login response: {raw[:300]}'

    token = None
    if isinstance(data, dict):
        d = data.get('data')
        if isinstance(d, dict):
            token = d.get('jwtToken') or d.get('jwt') or d.get('token')
        if not token:
            token = data.get('jwtToken') or data.get('jwt')
    if not token or not isinstance(token, str):
        return None, 'Login OK but no jwtToken in response (check AsyncOS version / Swagger).'
    return token.strip(), ''


def esa_config_query_string(settings: Optional[dict[str, str]] = None) -> str:
    """
    Query string for config/dictionaries APIs (Cisco Secure Email API Guide).
    standalone: device_type=esa only; cluster: &mode=cluster; group/machine: + required params.
    """
    g = settings or {}
    mode = (g.get('esa_deployment_mode') or 'standalone').strip().lower()
    if mode not in ESA_DEPLOYMENT_MODES:
        mode = 'standalone'
    parts = ['device_type=esa']
    if mode == 'cluster':
        parts.append('mode=cluster')
    elif mode == 'group':
        parts.append('mode=group')
        gn = (g.get('esa_group_name') or '').strip()
        if gn:
            parts.append(f'group_name={quote(gn, safe="")}')
    elif mode == 'machine':
        parts.append('mode=machine')
        hn = (g.get('esa_host_name') or '').strip()
        if hn:
            parts.append(f'host_name={quote(hn, safe="")}')
    return '&'.join(parts)


def _dictionary_words_path(dictionary_name: str, settings: Optional[dict[str, str]] = None) -> str:
    enc = quote(dictionary_name, safe='')
    qs = esa_config_query_string(settings)
    return f'config/dictionaries/{enc}/words?{qs}'


def _esa_words_add_body(words: list[str]) -> bytes:
    """POST add: each term is a list entry, e.g. [["a"], ["b"]] (Cisco API Guide)."""
    entries = [[w] for w in words if w]
    return json.dumps({'data': {'words': entries}}).encode('utf-8')


def _esa_words_delete_body(words: list[str]) -> bytes:
    """DELETE: flat string list-not the same shape as POST (Cisco API Guide)."""
    flat = [w for w in words if w]
    return json.dumps({'data': {'words': flat}}).encode('utf-8')


def esa_api_call(
    base_url: str,
    jwt: str,
    method: str,
    path_pattern: str,
    body: Optional[bytes],
    verify_ssl: bool,
) -> tuple[bool, str]:
    base = _base_url_normalize(base_url)
    rel = (path_pattern or '').strip().lstrip('/')
    if not rel:
        return False, 'Path pattern is empty'
    if '{dictionary}' in rel:
        return False, 'Path still contains {dictionary} placeholder (internal error)'
    url = f'{base}/{rel}'
    m = (method or 'POST').strip().upper()
    ctx = _ssl_context(verify_ssl)
    if m in ('GET', 'HEAD'):
        data = None
    else:
        data = body
    req = urllib.request.Request(url, data=data, method=m)
    apply_user_agent_to_request(req)
    req.add_header('jwttoken', jwt)
    if body is not None and m not in ('GET', 'HEAD'):
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC, context=ctx) as resp:
            code = resp.getcode()
            _ = resp.read()
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode('utf-8', errors='replace')[:800]
        except Exception:
            err_body = ''
        if e.code in (404, 410) and m == 'DELETE':
            return True, f'HTTP {e.code} (treat as already removed)'
        return False, f'HTTP {e.code} {e.reason} {err_body}'
    except urllib.error.URLError as e:
        return False, str(e.reason or e)
    except Exception as e:
        return False, str(e)
    if 200 <= code < 300:
        return True, f'HTTP {code}'
    return False, f'HTTP {code}'


def esa_push_add_by_dictionary(
    by_dictionary: dict[str, set[str]],
    *,
    settings: Optional[dict[str, str]] = None,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> tuple[bool, str]:
    """One login, then one POST per dictionary with all words for that dictionary."""
    g = settings or esa_settings_dict()
    if g.get('esa_enabled', '').strip().lower() not in ('true', '1', 'yes'):
        return True, 'skipped (disabled)'
    base = g.get('esa_base_url', '').strip()
    user = g.get('esa_username', '').strip()
    pw = g.get('esa_passphrase', '').strip()
    verify_ssl = g.get('esa_verify_ssl', 'true').strip().lower() in ('true', '1', 'yes')
    if not by_dictionary:
        return True, 'nothing to add'
    jwt, err = esa_login(base, user, pw, verify_ssl)
    if not jwt:
        return False, err or 'login failed'
    all_ok = True
    last_msg = ''
    for dname in sorted(by_dictionary.keys()):
        words = sorted(w for w in by_dictionary[dname] if w)
        if not words:
            continue
        path = _dictionary_words_path(dname, g)
        body = _esa_words_add_body(words)
        ok, msg = esa_api_call(base, jwt, 'POST', path, body, verify_ssl)
        if audit_log_fn:
            audit_log_fn(
                'esa_dict_add_ok' if ok else 'esa_dict_add_fail',
                f'dict={dname} n={len(words)} {msg[:200]}',
            )
        if not ok:
            all_ok = False
            last_msg = msg
            logger.warning('ESA dictionary add failed dict=%s count=%s: %s', dname, len(words), msg)
    return all_ok, last_msg or 'ok'


def esa_push_remove_by_dictionary(
    by_dictionary: dict[str, set[str]],
    *,
    settings: Optional[dict[str, str]] = None,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> tuple[bool, str]:
    """One login, then one DELETE per dictionary with all words for that dictionary."""
    g = settings or esa_settings_dict()
    if g.get('esa_enabled', '').strip().lower() not in ('true', '1', 'yes'):
        return True, 'skipped (disabled)'
    base = g.get('esa_base_url', '').strip()
    user = g.get('esa_username', '').strip()
    pw = g.get('esa_passphrase', '').strip()
    verify_ssl = g.get('esa_verify_ssl', 'true').strip().lower() in ('true', '1', 'yes')
    if not by_dictionary:
        return True, 'nothing to remove'
    jwt, err = esa_login(base, user, pw, verify_ssl)
    if not jwt:
        return False, err or 'login failed'
    all_ok = True
    last_msg = ''
    for dname in sorted(by_dictionary.keys()):
        words = sorted(w for w in by_dictionary[dname] if w)
        if not words:
            continue
        path = _dictionary_words_path(dname, g)
        body = _esa_words_delete_body(words)
        ok, msg = esa_api_call(base, jwt, 'DELETE', path, body, verify_ssl)
        if audit_log_fn:
            audit_log_fn(
                'esa_dict_remove_ok' if ok else 'esa_dict_remove_fail',
                f'dict={dname} n={len(words)} {msg[:200]}',
            )
        if not ok:
            all_ok = False
            last_msg = msg
            logger.warning('ESA dictionary remove failed dict=%s count=%s: %s', dname, len(words), msg)
    return all_ok, last_msg or 'ok'


def esa_add_word(
    dictionary_name: str,
    word: str,
    *,
    settings: Optional[dict[str, str]] = None,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> tuple[bool, str]:
    w = (word or '').strip()
    if not w:
        return True, 'empty word'
    return esa_push_add_by_dictionary(
        {dictionary_name: {w}}, settings=settings, audit_log_fn=audit_log_fn
    )


def esa_remove_word(
    dictionary_name: str,
    word: str,
    *,
    settings: Optional[dict[str, str]] = None,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> tuple[bool, str]:
    w = (word or '').strip()
    if not w:
        return True, 'empty word'
    return esa_push_remove_by_dictionary(
        {dictionary_name: {w}}, settings=settings, audit_log_fn=audit_log_fn
    )


def esa_test_connection(settings: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Return { success, steps: [{step, status, message}] } for admin UI."""
    g = settings or esa_settings_dict()
    steps: list[dict[str, str]] = []
    base = g.get('esa_base_url', '').strip()
    user = g.get('esa_username', '').strip()
    verify_ssl = g.get('esa_verify_ssl', 'true').strip().lower() in ('true', '1', 'yes')
    if not base:
        steps.append({'step': 'config', 'status': 'fail', 'message': 'esa_base_url is empty'})
        return {'success': False, 'steps': steps}
    jwt, err = esa_login(base, user, g.get('esa_passphrase', '').strip(), verify_ssl)
    if not jwt:
        steps.append({'step': 'login', 'status': 'fail', 'message': err or 'failed'})
        return {'success': False, 'steps': steps}
    steps.append({'step': 'login', 'status': 'ok', 'message': 'JWT obtained'})
    qs = esa_config_query_string(g)
    probe_url = f'{_base_url_normalize(base)}/config/dictionaries?{qs}'
    ctx = _ssl_context(verify_ssl)
    req = urllib.request.Request(probe_url, method='GET')
    apply_user_agent_to_request(req)
    req.add_header('jwttoken', jwt)
    req.add_header('Accept', '*/*')
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC, context=ctx) as resp:
            code = resp.getcode()
            if 200 <= code < 300:
                steps.append({
                    'step': 'dictionaries',
                    'status': 'ok',
                    'message': f'HTTP {code} (?{qs})',
                })
                return {'success': True, 'steps': steps}
            steps.append({'step': 'dictionaries', 'status': 'fail', 'message': f'HTTP {code} (?{qs})'})
            return {'success': False, 'steps': steps}
    except urllib.error.HTTPError as e:
        steps.append({'step': 'dictionaries', 'status': 'fail', 'message': f'HTTP {e.code} (?{qs})'})
        return {'success': False, 'steps': steps}
    except Exception as e:
        steps.append({'step': 'dictionaries', 'status': 'fail', 'message': f'{str(e)[:240]} (?{qs})'})
        return {'success': False, 'steps': steps}


def sync_add_batch(
    contexts: list[dict[str, Any]],
    *,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> None:
    """Group IOC creates by ESA dictionary; one login and one POST per dictionary."""
    g = esa_settings_dict()
    if g.get('esa_enabled', '').strip().lower() not in ('true', '1', 'yes'):
        return
    misp_sync = (_get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip().lower()
    skip_misp = g.get('esa_skip_misp_sync', 'true').strip().lower() in ('true', '1', 'yes')
    mappings = parse_mappings(g.get('esa_mappings', '[]'))
    by_dict: defaultdict[str, set[str]] = defaultdict(set)
    retry_contexts: list[dict[str, Any]] = []
    for ctx in contexts:
        if not isinstance(ctx, dict):
            continue
        ioc_type = (ctx.get('ioc_type') or ctx.get('type') or '').strip()
        analyst = (ctx.get('analyst') or '').strip()
        if skip_misp and analyst.lower() == misp_sync:
            continue
        value = (ctx.get('value') or '').strip()
        word = normalize_dictionary_word(ioc_type, value)
        if not word:
            continue
        retry_contexts.append({'action': 'create', 'type': ioc_type, 'value': value, 'analyst': analyst})
        for dname in dictionary_names_for_ioc_type(mappings, ioc_type):
            by_dict[dname].add(word)
    if not by_dict:
        return
    ok, msg = esa_push_add_by_dictionary(by_dict, settings=g, audit_log_fn=audit_log_fn)
    try:
        from utils.integration_telemetry import record_vendor_push_attempt, record_vendor_push_if_applicable

        word_count = sum(len(words) for words in by_dict.values())
        record_vendor_push_attempt(
            'cisco_esa',
            data_kind='IOC',
            ok=ok,
            message=msg,
            count=word_count or None,
        )
        record_vendor_push_if_applicable('cisco_esa', ok, msg)
    except Exception:
        logger.debug('ESA push telemetry failed', exc_info=True)
    if not ok and retry_contexts:
        try:
            from utils.integration_retry import enqueue_integration_retries

            enqueue_integration_retries('esa', [(c, msg) for c in retry_contexts], get_setting=_get_setting)
        except Exception:
            logger.exception('ESA batch enqueue retry failed')


def sync_add_for_ioc(
    ioc_type: str,
    value: str,
    analyst: str,
    *,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> None:
    sync_add_batch(
        [{'ioc_type': ioc_type, 'value': value, 'analyst': analyst}],
        audit_log_fn=audit_log_fn,
    )


def sync_remove_batch(
    rows: list[tuple[str, str]],
    *,
    settings: Optional[dict[str, str]] = None,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> None:
    """rows: (ioc_type, value). One login and one DELETE per dictionary."""
    g = settings or esa_settings_dict()
    if g.get('esa_enabled', '').strip().lower() not in ('true', '1', 'yes'):
        return
    mappings = parse_mappings(g.get('esa_mappings', '[]'))
    by_dict: defaultdict[str, set[str]] = defaultdict(set)
    retry_contexts: list[dict[str, Any]] = []
    for ioc_type, value in rows:
        word = normalize_dictionary_word(ioc_type, value or '')
        if not word:
            continue
        retry_contexts.append({'action': 'remove', 'type': ioc_type, 'value': (value or '').strip()})
        for dname in dictionary_names_for_ioc_type(mappings, ioc_type):
            by_dict[dname].add(word)
    if not by_dict:
        return
    ok, msg = esa_push_remove_by_dictionary(by_dict, settings=g, audit_log_fn=audit_log_fn)
    try:
        from utils.integration_telemetry import record_vendor_push_attempt, record_vendor_push_if_applicable

        word_count = sum(len(words) for words in by_dict.values())
        record_vendor_push_attempt(
            'cisco_esa',
            data_kind='IOC',
            ok=ok,
            message=msg,
            count=word_count or None,
        )
        record_vendor_push_if_applicable('cisco_esa', ok, msg)
    except Exception:
        logger.debug('ESA remove telemetry failed', exc_info=True)
    if not ok and retry_contexts:
        try:
            from utils.integration_retry import enqueue_integration_retries

            enqueue_integration_retries('esa', [(c, msg) for c in retry_contexts], get_setting=_get_setting)
        except Exception:
            logger.exception('ESA remove enqueue retry failed')


def sync_remove_for_ioc(
    ioc_type: str,
    value: str,
    *,
    settings: Optional[dict[str, str]] = None,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> None:
    sync_remove_batch([(ioc_type, value)], settings=settings, audit_log_fn=audit_log_fn)


def process_expired_ioc_rows_for_esa(
    rows: list[tuple[str, str]],
    settings: dict[str, str],
    *,
    log_fn: Optional[Callable[[str], None]] = None,
) -> None:
    """rows: list of (ioc_type, value). Uses settings from SQLite (no Flask)."""
    if settings.get('esa_enabled', '').strip().lower() not in ('true', '1', 'yes'):
        return
    if settings.get('esa_cleanup_on_expire', 'true').strip().lower() not in ('true', '1', 'yes'):
        return

    def _audit(action: str, detail: str) -> None:
        if log_fn:
            log_fn(f'{action} {detail}')

    sync_remove_batch(rows, settings=settings, audit_log_fn=_audit)


def schedule_esa_dictionary_after_submission(app, **kwargs: Any) -> None:
    """Background: add IOC value to mapped ESA dictionaries."""
    ioc_type = (kwargs.get('ioc_type') or '').strip()
    value = (kwargs.get('value') or '').strip()
    analyst = (kwargs.get('analyst') or '').strip()
    if not ioc_type or not value:
        return
    if _get_setting('esa_enabled', 'false').strip().lower() not in ('true', '1', 'yes'):
        return
    try:
        app_obj = app._get_current_object()
    except Exception:
        app_obj = app

    def _worker():
        import app as _app
        audit = _app.audit_log
        with app_obj.app_context():
            try:
                sync_add_for_ioc(ioc_type, value, analyst, audit_log_fn=audit)
            except Exception:
                logger.exception('ESA dictionary background add failed')

    threading.Thread(target=_worker, daemon=True).start()


def schedule_esa_dictionary_batch(app, contexts: list[dict[str, Any]]) -> None:
    if not contexts:
        return
    if _get_setting('esa_enabled', 'false').strip().lower() not in ('true', '1', 'yes'):
        return
    try:
        app_obj = app._get_current_object()
    except Exception:
        app_obj = app

    def _worker():
        import app as _app
        audit = _app.audit_log
        with app_obj.app_context():
            try:
                sync_add_batch(contexts, audit_log_fn=audit)
            except Exception:
                logger.exception('ESA dictionary batch add failed')

    threading.Thread(target=_worker, daemon=True).start()


def schedule_esa_remove_after_revoke(app, ioc_type: str, value: str) -> None:
    if _get_setting('esa_enabled', 'false').strip().lower() not in ('true', '1', 'yes'):
        return
    try:
        app_obj = app._get_current_object()
    except Exception:
        app_obj = app

    def _worker():
        import app as _app
        audit = _app.audit_log
        with app_obj.app_context():
            try:
                sync_remove_for_ioc(ioc_type, value, audit_log_fn=audit)
            except Exception:
                logger.exception('ESA dictionary background remove failed')

    threading.Thread(target=_worker, daemon=True).start()
