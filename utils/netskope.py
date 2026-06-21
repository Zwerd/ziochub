"""
Netskope cloud SWG — outbound IOC push via tenant REST API.

Admin fields live in ``system_settings`` under ``netskope_*`` (Integrations → Push IOC → Netskope).

**URL / IP / Domain / URL IOC types** → REST API V2 URL List:
  - ``PATCH /api/v2/policy/urllist/{id}/append`` (create)
  - ``PATCH /api/v2/policy/urllist/{id}/replace`` (remove / retraction)
  - ``POST /api/v2/policy/urllist/deploy`` (apply pending changes)

**Hash IOC (MD5 / SHA256)** → REST API V1 File Hash List:
  - ``POST /api/v1/updateFileHashList`` (replaces the **entire** list — ZIoCHub keeps a local
    cache of hashes it pushed and sends the merged set; use a dedicated list name for ZIoCHub)

Auth header: ``Netskope-API-Token`` (RBAC v2 token; v1 hash API may require a separate v1 token).

Invoked from ``utils.outbound_ioc.schedule_auxiliary_vendor_integrations``.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from utils.http_identity import configure_requests_session, ensure_user_agent

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SEC = 45
REQUEST_TIMEOUT_TEST_SEC = 20
URL_APPEND_BATCH_SIZE = 100
HASH_CACHE_SETTING_KEY = 'netskope_hash_cache_json'
_TEST_URL_VALUE = 'ziochub-connectivity-test.invalid'

_MD5_RE = re.compile(r'^[a-fA-F0-9]{32}$')
_SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')

_SUPPORTED_URL_IOC_TYPES = frozenset({'Domain', 'IP', 'URL'})


def _get_setting(key: str, default: str = '') -> str:
    import app as _app
    return _app._get_setting(key, default)


def _set_setting(key: str, value: str) -> None:
    import app as _app
    _app._set_setting(key, value)


def sanitize_netskope_base_url(raw: str) -> str:
    """Tenant base URL, e.g. https://yourorg.goskope.com (no trailing path)."""
    b = (raw or '').strip()
    if any(ch.isspace() for ch in b):
        b = ''.join(b.split())
    if b and '://' not in b:
        b = 'https://' + b
    b = b.rstrip('/')
    for suffix in ('/api/v2', '/api/v1', '/api'):
        if b.lower().endswith(suffix):
            b = b[: -len(suffix)].rstrip('/')
    return b


def netskope_enabled(settings: Optional[dict[str, str]] = None) -> bool:
    g = settings or netskope_settings_dict()
    return (g.get('netskope_enabled', 'false') or 'false').strip().lower() in ('true', '1', 'yes')


def netskope_settings_dict() -> dict[str, str]:
    keys = (
        'netskope_enabled',
        'netskope_base_url',
        'netskope_api_token_v2',
        'netskope_api_token_v1',
        'netskope_urllist_id',
        'netskope_hash_list_name',
        'netskope_hash_push_enabled',
        'netskope_deploy_on_push',
        'netskope_verify_ssl',
        'netskope_display_name',
    )
    return {k: _get_setting(k, '') for k in keys}


def _verify_ssl(g: dict[str, str]) -> bool:
    return (g.get('netskope_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')


def _deploy_on_push(g: dict[str, str]) -> bool:
    raw = (g.get('netskope_deploy_on_push') or 'true').strip().lower()
    return raw in ('true', '1', 'yes', '')


def _hash_push_enabled(g: dict[str, str]) -> bool:
    raw = (g.get('netskope_hash_push_enabled') or 'true').strip().lower()
    return raw in ('true', '1', 'yes', '')


def _v2_token(g: dict[str, str]) -> str:
    return (g.get('netskope_api_token_v2') or '').strip()


def _v1_token(g: dict[str, str]) -> str:
    t = (g.get('netskope_api_token_v1') or '').strip()
    return t or _v2_token(g)


def _api_base(g: dict[str, str]) -> str:
    return sanitize_netskope_base_url(g.get('netskope_base_url', ''))


def _urllist_id(g: dict[str, str]) -> str:
    return (g.get('netskope_urllist_id') or '').strip()


def _hash_list_name(g: dict[str, str]) -> str:
    return (g.get('netskope_hash_list_name') or '').strip()


def netskope_config_ready(g: Optional[dict[str, str]] = None) -> bool:
    g = g or netskope_settings_dict()
    if not _api_base(g) or not _v2_token(g):
        return False
    if not _urllist_id(g) and not (_hash_push_enabled(g) and _hash_list_name(g) and _v1_token(g)):
        return False
    return bool(_urllist_id(g) or (_hash_push_enabled(g) and _hash_list_name(g)))


def classify_hash(value: str) -> Optional[str]:
    v = (value or '').strip()
    if _SHA256_RE.match(v):
        return 'sha256'
    if _MD5_RE.match(v):
        return 'md5'
    return None


def normalize_urllist_entry(ioc_type: str, value: str) -> Optional[str]:
    """
    Map ZIoCHub IOC to a Netskope URL List entry.

    See Netskope URL List formatting rules (domain, URL with scheme, IP).
    """
    typ = (ioc_type or '').strip()
    raw = (value or '').strip()
    if not raw or typ not in _SUPPORTED_URL_IOC_TYPES:
        return None
    if typ == 'IP':
        return raw.split('/')[0].strip()
    if typ == 'Domain':
        host = raw.lower()
        if host.startswith('http://') or host.startswith('https://'):
            try:
                parsed = urlparse(host)
                host = (parsed.hostname or '').strip()
            except Exception:
                return None
        host = host.rstrip('.')
        if host.startswith('*.'):
            host = host[2:]
        return host or None
    if typ == 'URL':
        u = raw
        if not u.lower().startswith(('http://', 'https://')):
            u = 'https://' + u.lstrip('/')
        try:
            parsed = urlparse(u)
            if not parsed.netloc:
                return None
        except Exception:
            return None
        return u
    return None


def _session(verify_ssl: bool) -> requests.Session:
    sess = requests.Session()
    configure_requests_session(sess)
    sess.verify = verify_ssl
    return sess


def _headers_v2(token: str) -> dict[str, str]:
    ensure_user_agent()
    return {
        'Netskope-API-Token': token,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }


def _request_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    json_body: Any = None,
    timeout: float = REQUEST_TIMEOUT_SEC,
) -> tuple[int, Any, str]:
    try:
        r = session.request(method, url, headers=headers, json=json_body, timeout=timeout)
    except requests.RequestException as e:
        return 0, None, str(e)[:300]
    text = (r.text or '')[:500]
    try:
        body = r.json() if r.content else None
    except ValueError:
        body = text
    return r.status_code, body, text


def _load_hash_cache() -> set[str]:
    raw = (_get_setting(HASH_CACHE_SETTING_KEY, '') or '').strip()
    if not raw:
        return set()
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return set()
    if not isinstance(data, list):
        return set()
    return {str(h).strip().lower() for h in data if str(h).strip()}


def _save_hash_cache(hashes: set[str]) -> None:
    ordered = sorted(hashes)
    _set_setting(HASH_CACHE_SETTING_KEY, json.dumps(ordered, ensure_ascii=False))


def _sync_hash_list(session: requests.Session, g: dict[str, str], hashes: set[str]) -> tuple[bool, str]:
    name = _hash_list_name(g)
    token = _v1_token(g)
    base = _api_base(g)
    if not name or not token or not base:
        return False, 'missing_hash_list_config'
    url = f'{base}/api/v1/updateFileHashList'
    payload = {
        'name': name,
        'list': ','.join(sorted(hashes)),
        'token': token,
    }
    status, _body, text = _request_json(session, 'POST', url, headers={'Content-Type': 'application/json'}, json_body=payload)
    if status in (200, 201) or (isinstance(_body, dict) and str(_body.get('status', '')).upper() == 'OK'):
        _save_hash_cache(hashes)
        return True, 'hash_list_updated'
    return False, f'HTTP {status}: {text[:200]}'


def _append_urls(
    session: requests.Session,
    g: dict[str, str],
    urls: list[str],
) -> tuple[bool, str]:
    list_id = _urllist_id(g)
    token = _v2_token(g)
    base = _api_base(g)
    if not list_id or not token or not base or not urls:
        return False, 'missing_urllist_config'
    url = f'{base}/api/v2/policy/urllist/{list_id}/append'
    body = {'data': {'urls': urls, 'type': 'exact'}}
    status, _resp, text = _request_json(
        session, 'PATCH', url, headers=_headers_v2(token), json_body=body,
    )
    if status not in (200, 201, 204):
        return False, f'urllist_append HTTP {status}: {text[:200]}'
    if _deploy_on_push(g):
        ok, msg = _deploy_urllist(session, g)
        if not ok:
            return False, f'append_ok_deploy_fail: {msg}'
    return True, 'urllist_appended'


def _replace_urls_remove(
    session: requests.Session,
    g: dict[str, str],
    urls: list[str],
) -> tuple[bool, str]:
    """Remove URLs via replace (Netskope CTE retraction pattern)."""
    list_id = _urllist_id(g)
    token = _v2_token(g)
    base = _api_base(g)
    if not list_id or not token or not base or not urls:
        return False, 'missing_urllist_config'
    url = f'{base}/api/v2/policy/urllist/{list_id}/replace'
    body = {'data': {'urls': urls, 'type': 'exact'}}
    status, _resp, text = _request_json(
        session, 'PATCH', url, headers=_headers_v2(token), json_body=body,
    )
    if status not in (200, 201, 204):
        return False, f'urllist_replace HTTP {status}: {text[:200]}'
    if _deploy_on_push(g):
        ok, msg = _deploy_urllist(session, g)
        if not ok:
            return False, f'replace_ok_deploy_fail: {msg}'
    return True, 'urllist_removed'


def _deploy_urllist(session: requests.Session, g: dict[str, str]) -> tuple[bool, str]:
    token = _v2_token(g)
    base = _api_base(g)
    if not token or not base:
        return False, 'missing_config'
    url = f'{base}/api/v2/policy/urllist/deploy'
    status, _resp, text = _request_json(session, 'POST', url, headers=_headers_v2(token))
    if status in (200, 201, 204):
        return True, 'deployed'
    return False, f'deploy HTTP {status}: {text[:200]}'


def _chunked(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def netskope_push_ioc_from_context(
    ioc: dict[str, Any],
    *,
    from_retry: bool = False,
) -> tuple[bool, str]:
    ok, msg = _netskope_push_inner(ioc)
    if not ok and not from_retry:
        try:
            from utils.integration_retry import enqueue_integration_retry, integration_is_retriable_failure
            if integration_is_retriable_failure(msg):
                enqueue_integration_retry('netskope', ioc, msg, get_setting=_get_setting)
        except Exception:
            logger.exception('Netskope enqueue retry failed')
    if ok:
        _record_distribution(ioc)
    return ok, msg


def _record_distribution(ioc: dict[str, Any]) -> None:
    try:
        g = netskope_settings_dict()
        from utils.downstream import mark_api_distribution_removed, record_api_distribution_events
        name = (g.get('netskope_display_name') or '').strip() or 'Netskope'
        action = (str(ioc.get('action') or 'create')).strip().lower()
        if action in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove'):
            mark_api_distribution_removed([ioc], vendor_id='netskope', display_name=name, api_source='netskope')
        else:
            record_api_distribution_events([ioc], vendor_id='netskope', display_name=name, api_source='netskope')
    except Exception:
        pass


def _netskope_push_inner(ioc: dict[str, Any]) -> tuple[bool, str]:
    if not netskope_enabled():
        return True, 'disabled'
    g = netskope_settings_dict()
    if not netskope_config_ready(g):
        return True, 'skipped_incomplete_config'

    action = (str(ioc.get('action') or 'create')).strip().lower()
    ioc_type = (str(ioc.get('type') or '')).strip()
    value = (str(ioc.get('value') or '')).strip()
    if not value:
        return False, 'missing_type_or_value'

    verify = _verify_ssl(g)
    session = _session(verify)

    if ioc_type == 'Hash':
        if not _hash_push_enabled(g) or not _hash_list_name(g):
            return True, 'skip_hash_push_disabled'
        h = value.lower()
        if not classify_hash(h):
            return True, 'skip_unsupported_hash_length'
        cache = _load_hash_cache()
        is_remove = action in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove')
        if is_remove:
            if h not in cache:
                return True, 'skip_hash_not_in_cache'
            cache.discard(h)
        else:
            cache.add(h)
        ok, msg = _sync_hash_list(session, g, cache)
        return ok, msg

    entry = normalize_urllist_entry(ioc_type, value)
    if not entry:
        return True, f'skip_unsupported_type_{ioc_type.lower()}'
    if not _urllist_id(g):
        return True, 'skip_no_urllist_id'

    is_remove = action in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove')
    if is_remove:
        return _replace_urls_remove(session, g, [entry])
    return _append_urls(session, g, [entry])


def netskope_push_contexts_batch(
    contexts: list[dict[str, Any]],
    *,
    from_retry: bool = False,
) -> dict[str, Any]:
    if not contexts:
        return {'success': True, 'processed': 0, 'succeeded': 0, 'failed': 0}
    if not netskope_enabled():
        return {'success': True, 'processed': 0, 'succeeded': 0, 'failed': 0, 'message': 'disabled'}
    g = netskope_settings_dict()
    if not netskope_config_ready(g):
        return {
            'success': True,
            'processed': len(contexts),
            'succeeded': 0,
            'failed': 0,
            'message': 'skipped_incomplete_config',
        }

    verify = _verify_ssl(g)
    session = _session(verify)

    url_appends: list[str] = []
    url_removes: list[str] = []
    hash_adds: set[str] = set()
    hash_removes: set[str] = set()
    skipped = 0

    for ctx in contexts:
        if not isinstance(ctx, dict):
            continue
        action = (str(ctx.get('action') or 'create')).strip().lower()
        ioc_type = (str(ctx.get('type') or '')).strip()
        value = (str(ctx.get('value') or '')).strip()
        if not value:
            skipped += 1
            continue
        is_remove = action in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove')
        if ioc_type == 'Hash':
            h = value.lower()
            if not classify_hash(h):
                skipped += 1
                continue
            if is_remove:
                hash_removes.add(h)
            else:
                hash_adds.add(h)
            continue
        entry = normalize_urllist_entry(ioc_type, value)
        if not entry:
            skipped += 1
            continue
        if is_remove:
            url_removes.append(entry)
        else:
            url_appends.append(entry)

    failed = 0
    succeeded = 0
    all_failed: list[tuple[dict[str, Any], str]] = []

    if _urllist_id(g) and url_appends:
        for chunk in _chunked(url_appends, URL_APPEND_BATCH_SIZE):
            ok, msg = _append_urls(session, g, chunk)
            if ok:
                succeeded += len(chunk)
            else:
                failed += len(chunk)
                for u in chunk:
                    all_failed.append(({'type': 'URL', 'value': u, 'action': 'create'}, msg))

    if _urllist_id(g) and url_removes:
        for chunk in _chunked(url_removes, URL_APPEND_BATCH_SIZE):
            ok, msg = _replace_urls_remove(session, g, chunk)
            if ok:
                succeeded += len(chunk)
            else:
                failed += len(chunk)
                for u in chunk:
                    all_failed.append(({'type': 'URL', 'value': u, 'action': 'remove'}, msg))

    if _hash_push_enabled(g) and _hash_list_name(g) and (hash_adds or hash_removes):
        cache = _load_hash_cache()
        cache |= hash_adds
        cache -= hash_removes
        ok, msg = _sync_hash_list(session, g, cache)
        n_hash = len(hash_adds) + len(hash_removes)
        if ok:
            succeeded += n_hash
        else:
            failed += n_hash
            for h in hash_adds | hash_removes:
                all_failed.append(({'type': 'Hash', 'value': h, 'action': 'create'}, msg))

    processed = len(contexts) - skipped
    overall_ok = failed == 0
    summary_msg = f'batch ok={succeeded} fail={failed} skipped={skipped}'

    try:
        from utils.integration_telemetry import record_vendor_push_attempt, record_vendor_push_if_applicable
        record_vendor_push_attempt('netskope', data_kind='IOC', ok=overall_ok, message=summary_msg, count=processed)
        if overall_ok and succeeded:
            record_vendor_push_if_applicable('netskope', True, summary_msg)
    except Exception:
        pass

    if not from_retry and all_failed:
        try:
            from utils.integration_retry import enqueue_integration_retries
            enqueue_integration_retries('netskope', all_failed, get_setting=_get_setting)
        except Exception:
            logger.exception('Netskope batch enqueue retry failed')

    failed_keys = {
        (str(p.get('type') or ''), str(p.get('value') or '').lower(), str(p.get('action') or ''))
        for p, _m in all_failed
    }
    if overall_ok or succeeded:
        for ctx in contexts:
            if not isinstance(ctx, dict):
                continue
            key = (
                str(ctx.get('type') or ''),
                str(ctx.get('value') or '').lower(),
                str(ctx.get('action') or 'create'),
            )
            if key in failed_keys:
                continue
            typ = key[0]
            val = str(ctx.get('value') or '').strip()
            if not val:
                continue
            if typ == 'Hash' and not classify_hash(val):
                continue
            if typ != 'Hash' and not normalize_urllist_entry(typ, val):
                continue
            _record_distribution(ctx)

    return {
        'success': overall_ok,
        'processed': processed,
        'succeeded': succeeded,
        'failed': failed,
        'skipped': skipped,
        'message': summary_msg,
    }


def netskope_test_connection(
    settings: Optional[dict[str, str]] = None,
    *,
    verify_ssl: Optional[bool] = None,
    roundtrip: bool = False,
) -> dict[str, Any]:
    """Admin test: list URL lists, verify configured ID, optional append+replace roundtrip."""
    g = settings or netskope_settings_dict()
    steps: list[dict[str, str]] = []
    base = _api_base(g)
    token = _v2_token(g)

    if not base:
        steps.append({'step': 'config', 'status': 'fail', 'message': 'Tenant base URL is required (https://yourorg.goskope.com)'})
        return {'success': False, 'steps': steps}
    if not token:
        steps.append({'step': 'config', 'status': 'fail', 'message': 'API token (V2) is required'})
        return {'success': False, 'steps': steps}

    steps.append({'step': 'config', 'status': 'ok', 'message': f'Base URL: {base}'})

    if verify_ssl is None:
        verify_ssl = _verify_ssl(g)

    session = _session(verify_ssl)
    list_url = f'{base}/api/v2/policy/urllist?field=id,name'
    status, body, text = _request_json(
        session, 'GET', list_url, headers=_headers_v2(token), timeout=REQUEST_TIMEOUT_TEST_SEC,
    )
    if status != 200:
        steps.append({
            'step': 'urllist_list',
            'status': 'fail',
            'message': f'HTTP {status} GET /api/v2/policy/urllist — {text[:200]} (enable URL List API V2 with Netskope Support if needed)',
        })
        return {'success': False, 'steps': steps}

    steps.append({'step': 'urllist_list', 'status': 'ok', 'message': f'HTTP {status} — URL lists reachable'})

    configured_id = _urllist_id(g)
    if configured_id:
        found = False
        if isinstance(body, list):
            for item in body:
                if str(item.get('id', '')) == configured_id:
                    found = True
                    steps.append({
                        'step': 'urllist_id',
                        'status': 'ok',
                        'message': f'URL List id={configured_id} name={item.get("name", "?")}',
                    })
                    break
        if not found:
            steps.append({
                'step': 'urllist_id',
                'status': 'warn',
                'message': f'Configured URL List id={configured_id} not found in list response (may still work if pending)',
            })

    hash_name = _hash_list_name(g)
    if hash_name and _hash_push_enabled(g):
        v1 = _v1_token(g)
        if v1:
            steps.append({
                'step': 'hash_list',
                'status': 'ok',
                'message': f'Hash list "{hash_name}" configured (V1 token present; push replaces full list from ZIoCHub cache)',
            })
        else:
            steps.append({'step': 'hash_list', 'status': 'warn', 'message': 'Hash list name set but no V1 API token'})

    if roundtrip and configured_id:
        ok_a, msg_a = _append_urls(session, g, [f'https://{_TEST_URL_VALUE}'])
        steps.append({
            'step': 'roundtrip_append',
            'status': 'ok' if ok_a else 'fail',
            'message': msg_a,
        })
        if ok_a:
            ok_r, msg_r = _replace_urls_remove(session, g, [f'https://{_TEST_URL_VALUE}'])
            steps.append({
                'step': 'roundtrip_remove',
                'status': 'ok' if ok_r else 'fail',
                'message': msg_r,
            })
            return {'success': ok_a and ok_r, 'steps': steps}
        return {'success': False, 'steps': steps}

    return {'success': True, 'steps': steps}
