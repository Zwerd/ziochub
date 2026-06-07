"""
Palo Alto Cortex XDR - IOC outbound integration via the **public** REST API.

Admin fields live in ``system_settings`` under ``cortex_xdr_*`` (Integrations -> Cortex XDR).

**Documented endpoints (Cortex XDR Platform APIs):** ZIoCHub uses only the publicly documented
``/public_api/v1/indicators/*`` endpoints, NOT the legacy ``tim_*`` aliases (the older TIM module
was merged into core XDR and modern tenants reject ``tim_insert_jsons`` with HTTP 403
``"Invalid API"``):

- Insert:  ``POST /public_api/v1/indicators/insert_jsons`` - body ``{"request_data": [{...}], "validate": true}``.
  Supported types: ``HASH``, ``IP``, ``DOMAIN_NAME``, ``FILENAME``. URL/PATH is NOT supported by
  this endpoint - it is only supported by ``indicators/insert`` which requires Instance Administrator
  permissions. ZIoCHub skips URL (and Email) pushes for now.
- Remove:  ``POST /public_api/v1/indicators/delete`` - body
  ``{"request_data": {"filters": [{"field": "indicator", "operator": "EQ", "value": ["..."]}]}}``.
- List:    ``POST /public_api/v1/indicators/get`` - also used by the Admin "Test connection" probe.

Each insert object uses keys ``indicator``, ``type``, ``severity`` (``INFO`` | ``LOW`` | ``MEDIUM`` |
``HIGH`` | ``CRITICAL``), ``reputation`` (``GOOD`` | ``BAD`` | ``SUSPICIOUS`` | ``UNKNOWN``),
optional ``expiration_date`` (epoch ms, or ``-1`` for tenant default TTL), and ``comment``.

**File hash blocklist (Hash IOC only):** in addition to IOC insert, optionally call the documented
``POST {base}/public_api/v1/hash_exceptions/blocklist/`` with ``request_data.hash_list`` (see *Block List
Files* / Cortex XSOAR ``xdr-blocklist-files`` / ``CoreIRApiModule.blocklist_files``). Revoke calls
``hash_exceptions/blocklist/remove/``. This is separate from the browser-only
``/api/webapp/response/hash_exceptions_statuses`` flow.

**Authentication:** Standard or Advanced API keys (see ``cortex_xdr_security_level``). Standard keys
send ``Authorization`` as the raw key; Advanced keys send ``Authorization`` as
``SHA256(api_key + nonce + timestamp)`` plus ``x-xdr-nonce`` and ``x-xdr-timestamp``. The IOC insert
call also sends ``x-iocs-source``; other calls use standard signing only.

``cortex_xdr_push_ioc_from_context`` is invoked from ``utils.outbound_ioc.schedule_auxiliary_vendor_integrations``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import string
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Any, Optional

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SEC = 45
# Shorter outbound timeout for Admin "Test connection" so Gunicorn (default 30s worker limit) returns JSON in time.
REQUEST_TIMEOUT_TEST_SEC = 15
_NONCE_LEN = 64

# Test-connection probe: ``indicators/get`` is the same documented IOC API that production
# uses for ``indicators/insert_jsons`` / ``indicators/delete``, so a 200 here proves real
# end-to-end readiness. The previous ``authentication-settings/get/settings`` probe required
# Instance Admin RBAC and returned 403 for normal IOC keys, masking the real status to operators.
_CORTEX_TEST_PROBE_SUBPATH = 'indicators/get'

# ZIoCHub IOC type -> Cortex ``type`` for /public_api/v1/indicators/insert_jsons.
# Note: URL is intentionally NOT mapped. The insert_jsons endpoint only supports
# HASH/IP/DOMAIN_NAME/FILENAME; PATH (URLs) requires the /indicators/insert endpoint which needs
# Instance Administrator permissions. URL pushes are skipped (logged as skip_unsupported_type_URL).
_IOC_TYPE_MAP: dict[str, str] = {
    'Domain': 'DOMAIN_NAME',
    'IP': 'IP',
    'Hash': 'HASH',
}

_DEFAULT_SEVERITY = 'HIGH'
_DEFAULT_REPUTATION = 'BAD'
_ALLOWED_SEVERITY = frozenset({'INFO', 'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'})
_ALLOWED_REPUTATION = frozenset({'GOOD', 'SUSPICIOUS', 'BAD', 'UNKNOWN'})

# Cortex XDR API key security levels (chosen in console: Settings -> Configurations -> API Keys -> Security Level).
# - 'advanced': Authorization = SHA256(api_key + nonce + timestamp), plus x-xdr-nonce + x-xdr-timestamp.
# - 'standard': Authorization = raw api_key. No nonce/timestamp/hash.
_SECURITY_LEVEL_ADVANCED = 'advanced'
_SECURITY_LEVEL_STANDARD = 'standard'
_DEFAULT_SECURITY_LEVEL = _SECURITY_LEVEL_ADVANCED

_COMMENT_MODE_FULL = 'full'
_COMMENT_MODE_ATTRIBUTION = 'attribution'
_COMMENT_MODE_ATTRIBUTION_META = 'attribution_meta'
_DEFAULT_COMMENT_MODE = _COMMENT_MODE_FULL
_RESYNC_COMMENT_SUFFIX = 're-synced by ZIoCHub'


def _normalize_security_level(raw: Optional[str]) -> str:
    s = (raw or '').strip().lower()
    return _SECURITY_LEVEL_STANDARD if s == _SECURITY_LEVEL_STANDARD else _SECURITY_LEVEL_ADVANCED


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


def cortex_xdr_enabled(settings: Optional[dict[str, str]] = None) -> bool:
    g = settings or cortex_xdr_settings_dict()
    return (g.get('cortex_xdr_enabled', 'false') or 'false').strip().lower() in ('true', '1', 'yes')


def cortex_xdr_settings_dict() -> dict[str, str]:
    keys = (
        'cortex_xdr_enabled',
        'cortex_xdr_base_url',
        'cortex_xdr_api_key_id',
        'cortex_xdr_api_key',
        'cortex_xdr_verify_ssl',
        'cortex_xdr_hash_blocklist_enabled',
        'cortex_xdr_security_level',
        'cortex_xdr_comment_mode',
    )
    return {k: _get_setting(k, '') for k in keys}


def _hash_blocklist_enabled(g: dict[str, str]) -> bool:
    raw = (g.get('cortex_xdr_hash_blocklist_enabled') or 'true').strip().lower()
    return raw in ('true', '1', 'yes')


def sanitize_cortex_base_url(raw: str) -> str:
    """Strip and remove all whitespace (common paste typo: ``https:// api-…``)."""
    b = (raw or '').strip()
    if any(ch.isspace() for ch in b):
        b = ''.join(b.split())
    return b.rstrip('/')


def _public_api_v1_root(base_url: str) -> str:
    b = sanitize_cortex_base_url(base_url)
    suf = '/public_api/v1'
    if b.endswith(suf):
        return b
    idx = b.find(suf + '/')
    if idx >= 0:
        return b[: idx + len(suf)]
    if b.endswith('/public_api'):
        return b + '/v1'
    return b + suf


def _cortex_test_probe_url(base_url: str) -> str:
    """URL for the Admin test probe. Uses the documented IOC API endpoint."""
    root = _public_api_v1_root(base_url)
    return root.rstrip('/') + '/' + _CORTEX_TEST_PROBE_SUBPATH


def _indicators_url(root_v1: str, suffix: str) -> str:
    s = suffix.lstrip('/')
    return root_v1.rstrip('/') + '/indicators/' + s


def _post_indicators(
    root_v1: str,
    api_key_id: str,
    api_key: str,
    verify_ssl: bool,
    path_suffix: str,
    body: dict[str, Any],
    *,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
    iocs_source: bool = True,
) -> tuple[int, Optional[dict[str, Any]], str]:
    """POST to ``/public_api/v1/indicators/<suffix>`` (e.g. ``insert_jsons``, ``delete``, ``get``)."""
    url = _indicators_url(root_v1, path_suffix)
    hdrs = _sign_headers(api_key_id, api_key, tim_source=iocs_source, security_level=security_level)
    return _http_json_post(url, body, hdrs, verify_ssl)


def _post_v1(
    root_v1: str,
    api_key_id: str,
    api_key: str,
    verify_ssl: bool,
    subpath: str,
    body: dict[str, Any],
    *,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
) -> tuple[int, Optional[dict[str, Any]], str]:
    """POST under ``/public_api/v1/<subpath>`` (no ``x-iocs-source``); auth per ``security_level``."""
    url = root_v1.rstrip('/') + '/' + subpath.lstrip('/')
    hdrs = _sign_headers(api_key_id, api_key, tim_source=False, security_level=security_level)
    return _http_json_post(url, body, hdrs, verify_ssl)


def _sign_headers(
    api_key_id: str,
    api_key: str,
    *,
    tim_source: bool,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
) -> dict[str, str]:
    """
    Build Cortex XDR public_api auth headers. ``security_level`` follows the value chosen
    when the API key was created in the Cortex console (Standard vs Advanced). Standard
    keys MUST NOT receive a signed Authorization or nonce/timestamp - Cortex rejects those
    as 401 even when the raw key is valid.
    """
    level = _normalize_security_level(security_level)
    h: dict[str, str] = {
        'x-xdr-auth-id': str(api_key_id),
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    if level == _SECURITY_LEVEL_STANDARD:
        h['Authorization'] = api_key
    else:
        nonce = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(_NONCE_LEN))
        ts = str(int(datetime.now(timezone.utc).timestamp() * 1000))
        digest = hashlib.sha256(f'{api_key}{nonce}{ts}'.encode('utf-8')).hexdigest()
        h['x-xdr-timestamp'] = ts
        h['x-xdr-nonce'] = nonce
        h['Authorization'] = digest
    if tim_source:
        h['x-iocs-source'] = 'ziochub'
    return h


def _http_json_post(
    url: str,
    body: dict[str, Any],
    headers: dict[str, str],
    verify_ssl: bool,
    *,
    timeout_sec: Optional[float] = None,
) -> tuple[int, Optional[dict[str, Any]], str]:
    raw = json.dumps(body, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(url, data=raw, method='POST')
    for k, v in headers.items():
        req.add_header(k, v)
    ctx = _ssl_context(verify_ssl)
    timeout = REQUEST_TIMEOUT_SEC if timeout_sec is None else timeout_sec
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code = resp.getcode()
            txt = resp.read().decode('utf-8', errors='replace')
            try:
                return code, json.loads(txt) if txt.strip() else {}, ''
            except json.JSONDecodeError:
                return code, None, txt[:500]
    except urllib.error.HTTPError as e:
        # 4xx/5xx with a real HTTP status. Must be caught BEFORE URLError since
        # HTTPError is a subclass of URLError - otherwise this branch is dead code
        # and Cortex 401/403/404 appear to the UI as opaque "Network error: <reason>".
        err = ''
        try:
            err = e.read()[:800].decode('utf-8', errors='replace')
        except Exception:
            pass
        try:
            parsed = json.loads(err) if err.strip() else None
        except json.JSONDecodeError:
            parsed = None
        return e.code, parsed, err[:500]
    except urllib.error.URLError as e:
        reason = getattr(e, 'reason', None)
        if isinstance(reason, ssl.SSLError):
            return 0, None, f'TLS error: {reason}'.strip()[:500]
        return 0, None, f'Network error: {reason or e}'.strip()[:500]


def _normalize_severity(raw: Optional[str]) -> str:
    s = (raw or _DEFAULT_SEVERITY).strip().upper()
    if s == 'INFORMATIONAL':
        s = 'INFO'
    if s not in _ALLOWED_SEVERITY:
        return _DEFAULT_SEVERITY
    return s


def _normalize_reputation(raw: Optional[str]) -> str:
    r = (raw or _DEFAULT_REPUTATION).strip().upper()
    if r not in _ALLOWED_REPUTATION:
        return _DEFAULT_REPUTATION
    return r


def _expiration_ms(expiration_iso: str) -> int:
    """Cortex TIM uses epoch milliseconds; ``-1`` means default TTL (like UI ``IS_DEFAULT_TTL``)."""
    s = (expiration_iso or '').strip()
    if not s:
        return -1
    try:
        if len(s) >= 10 and s[4] == '-' and s[7] == '-':
            day = s[:10]
            dt = datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return -1


def normalize_cortex_xdr_comment_mode(raw: Optional[str]) -> str:
    """Return a valid Cortex XDR IOC comment mode (admin save + form)."""
    s = (raw or '').strip().lower()
    if s in (_COMMENT_MODE_ATTRIBUTION, _COMMENT_MODE_ATTRIBUTION_META):
        return s
    return _COMMENT_MODE_FULL


def _normalize_comment_mode(raw: Optional[str]) -> str:
    return normalize_cortex_xdr_comment_mode(raw)


def _attribution_label(settings: Optional[dict[str, str]] = None) -> str:
    g = settings or cortex_xdr_settings_dict()
    dn = (g.get('cortex_xdr_display_name') or '').strip()
    return dn if dn else 'ZIoCHub IOC'


def _append_resync_suffix(comment: str) -> str:
    base = (comment or '').strip() or 'ZIoCHub IOC'
    if _RESYNC_COMMENT_SUFFIX in base:
        return base[:4000]
    return f'{base} | {_RESYNC_COMMENT_SUFFIX}'[:4000]


def _tim_comment_from_context(ioc: dict[str, Any], *, resynced: bool = False) -> str:
    g = cortex_xdr_settings_dict()
    mode = _normalize_comment_mode(g.get('cortex_xdr_comment_mode'))
    label = _attribution_label(g)
    tid = (ioc.get('ticket_id') or '').strip()
    an = (ioc.get('analyst') or '').strip()
    cm = (ioc.get('comment') or '').strip()

    if mode == _COMMENT_MODE_ATTRIBUTION:
        out = label
    elif mode == _COMMENT_MODE_ATTRIBUTION_META:
        meta: list[str] = [label]
        if tid:
            meta.append(f'ticket={tid}')
        if an:
            meta.append(f'analyst={an}')
        out = ' | '.join(meta)
    else:
        parts: list[str] = []
        if tid:
            parts.append(f'ticket={tid}')
        if an:
            parts.append(f'analyst={an}')
        if cm:
            parts.append(cm)
        out = ' | '.join(parts) if parts else label

    if resynced:
        out = _append_resync_suffix(out)
    return out[:4000]


def _ioc_to_tim_record(ioc: dict[str, Any], *, resynced: bool = False) -> Optional[dict[str, Any]]:
    zt = (ioc.get('type') or '').strip()
    x_type = _IOC_TYPE_MAP.get(zt)
    if not x_type:
        return None
    val = (ioc.get('value') or '').strip()
    if not val:
        return None
    rec: dict[str, Any] = {
        'indicator': val,
        'type': x_type,
        'severity': _normalize_severity(_get_setting('cortex_xdr_default_severity', '') or None),
        'reputation': _normalize_reputation(_get_setting('cortex_xdr_default_reputation', '') or None),
        'comment': _tim_comment_from_context(ioc, resynced=resynced),
    }
    exp_ms = _expiration_ms(str(ioc.get('expiration_date') or ''))
    rec['expiration_date'] = exp_ms
    return rec


def _interpret_tim_reply(data: Optional[dict[str, Any]], *, op: str) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, f'{op}: empty or non-JSON response'
    rep = data.get('reply')
    if not isinstance(rep, dict):
        return False, f'{op}: missing reply object'
    errs = rep.get('validation_errors')
    if isinstance(errs, list) and errs:
        bits = []
        for it in errs[:5]:
            if isinstance(it, dict):
                bits.append(f"{it.get('indicator', '?')}: {it.get('error', it)}")
            else:
                bits.append(str(it))
        msg = '; '.join(bits)[:900]
        logger.warning('Cortex XDR %s validation_errors: %s', op, msg)
    if rep.get('success') is True:
        return True, f'{op}_ok'
    err = rep.get('err_msg') or rep.get('error') or rep.get('message')
    if err:
        return False, f'{op}: {err}'[:900]
    return False, f'{op}: success=false'


def _looks_like_indicator_already_exists(data: Optional[dict[str, Any]], raw: str) -> bool:
    """True if Cortex response suggests the indicator row already exists (may be stale after our delete)."""
    parts: list[str] = [(raw or '').lower()]
    if isinstance(data, dict):
        rep = data.get('reply')
        if isinstance(rep, dict):
            for err in rep.get('validation_errors') or []:
                if isinstance(err, dict):
                    parts.append((err.get('error') or '').lower())
                    parts.append((err.get('indicator') or '').lower())
        try:
            parts.append(json.dumps(data, ensure_ascii=False).lower())
        except (TypeError, ValueError):
            pass
    blob = ' '.join(parts)
    for needle in ('already exist', 'indicator already', 'ioc already exists'):
        if needle in blob:
            return True
    return False


def _delete_indicator_by_value(
    root: str,
    key_id: str,
    api_key: str,
    verify_ssl: bool,
    value: str,
    *,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
) -> tuple[bool, str]:
    """Delete one indicator via ``indicators/delete`` (filter on indicator value)."""
    delete_body = {
        'request_data': {
            'filters': [
                {'field': 'indicator', 'operator': 'EQ', 'value': [value]},
            ],
        },
    }
    code, data, raw = _post_indicators(
        root, key_id, api_key, verify_ssl, 'delete',
        delete_body, security_level=security_level, iocs_source=False,
    )
    if code is not None and not (200 <= code < 300):
        return False, f'indicators/delete HTTP {code}: {raw[:240]}'
    ok, msg = _interpret_tim_reply(data, op='indicators/delete')
    if not ok:
        logger.warning('Cortex XDR indicators/delete failed: %s', msg)
    return ok, msg


def _normalize_hash_value(value: str) -> str:
    v = (value or '').strip()
    if len(v) == 64 and all(c in '0123456789abcdefABCDEF' for c in v):
        return v.lower()
    return v


def _interpret_hash_exception_reply(data: Optional[dict[str, Any]], op: str) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, f'{op}: not json'
    rep = data.get('reply')
    if isinstance(rep, dict):
        if rep.get('err_code') == 500:
            return False, f'{op}: {rep.get("err_msg", "500")}'[:900]
        if rep.get('success') is True:
            return True, f'{op}_ok'
        em = rep.get('err_msg') or rep.get('error')
        if em:
            return False, f'{op}: {em}'[:900]
    if rep is True:
        return True, f'{op}_ok'
    return False, f'{op}: unexpected reply'


def _attempt_insert_jsons(
    root: str,
    key_id: str,
    api_key: str,
    verify_ssl: bool,
    rec: dict[str, Any],
    *,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
) -> tuple[bool, str, Optional[dict[str, Any]], str]:
    """Single ``insert_jsons`` call. Returns (ok, message, parsed_json, raw_text)."""
    code, data, raw = _post_indicators(
        root,
        key_id,
        api_key,
        verify_ssl,
        'insert_jsons',
        {'request_data': [rec], 'validate': True},
        security_level=security_level,
        iocs_source=True,
    )
    if code is not None and not (200 <= code < 300):
        return False, f'insert_jsons HTTP {code}: {raw[:240]}', data, raw
    ok, msg = _interpret_tim_reply(data, op='insert_jsons')
    if ok and _looks_like_indicator_already_exists(data, raw):
        return False, f'insert_jsons duplicate: {msg}', data, raw
    return ok, msg, data, raw


def _push_insert_jsons(
    root: str,
    key_id: str,
    api_key: str,
    verify_ssl: bool,
    rec: dict[str, Any],
    value: str,
    *,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
) -> tuple[bool, str]:
    """
    Insert one IOC via ``indicators/insert_jsons``.

    After ZIoCHub deletes an IOC, Cortex may still retain a stale row so re-insert returns
    "already exists" without re-activating the block rule. On duplicate, delete then insert again.
    """
    ok, msg, data, raw = _attempt_insert_jsons(
        root, key_id, api_key, verify_ssl, rec, security_level=security_level,
    )
    if ok:
        return True, msg
    if not _looks_like_indicator_already_exists(data, raw):
        logger.warning('Cortex XDR insert_jsons failed: %s', msg)
        return False, msg

    logger.info(
        'Cortex XDR: insert_jsons duplicate for %r; delete then re-insert',
        value[:128],
    )
    _delete_indicator_by_value(
        root, key_id, api_key, verify_ssl, value, security_level=security_level,
    )
    rec_resync = dict(rec)
    rec_resync['comment'] = _append_resync_suffix(str(rec.get('comment') or ''))
    ok2, msg2, _, _ = _attempt_insert_jsons(
        root, key_id, api_key, verify_ssl, rec_resync, security_level=security_level,
    )
    if ok2:
        return True, f'reinsert_ok ({msg2})'
    logger.warning('Cortex XDR re-insert after duplicate failed: %s', msg2)
    return False, f'reinsert_after_duplicate: {msg2}'


def _hash_blocklist_add(
    root: str,
    key_id: str,
    api_key: str,
    verify_ssl: bool,
    ioc: dict[str, Any],
    hash_value: str,
    *,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
) -> tuple[bool, str]:
    cm = _tim_comment_from_context(ioc)
    inner: dict[str, Any] = {'hash_list': [_normalize_hash_value(hash_value)]}
    if cm:
        inner['comment'] = cm
    code, data, raw = _post_v1(
        root,
        key_id,
        api_key,
        verify_ssl,
        'hash_exceptions/blocklist/',
        {'request_data': inner},
        security_level=security_level,
    )
    if code is None or not (200 <= code < 300):
        return False, f'hash_blocklist HTTP {code}: {raw[:300]}'
    return _interpret_hash_exception_reply(data, 'hash_blocklist')


def _hash_blocklist_remove(
    root: str,
    key_id: str,
    api_key: str,
    verify_ssl: bool,
    hash_value: str,
    *,
    security_level: str = _DEFAULT_SECURITY_LEVEL,
) -> tuple[bool, str]:
    inner = {'hash_list': [_normalize_hash_value(hash_value)]}
    code, data, raw = _post_v1(
        root,
        key_id,
        api_key,
        verify_ssl,
        'hash_exceptions/blocklist/remove/',
        {'request_data': inner},
        security_level=security_level,
    )
    if code is None or not (200 <= code < 300):
        return False, f'hash_blocklist_remove HTTP {code}: {raw[:300]}'
    return _interpret_hash_exception_reply(data, 'hash_blocklist_remove')


def cortex_xdr_push_ioc_from_context(ioc: dict[str, Any]) -> tuple[bool, str]:
    """
    Push one IOC event using the documented IOC endpoints: ``indicators/insert_jsons`` on create
    and ``indicators/delete`` (filter-based) on revoke. For **Hash** IOCs only we additionally call
    Action Center ``hash_exceptions/blocklist`` (and ``.../remove`` on revoke).

    ``Email`` and ``URL`` IOCs are skipped (no supported type on ``insert_jsons`` for these).
    """
    ok, msg = _cortex_xdr_push_ioc_from_context_inner(ioc)
    try:
        from utils.integration_telemetry import record_vendor_push_attempt, record_vendor_push_if_applicable

        record_vendor_push_attempt('cortex_xdr', data_kind='IOC', ok=ok, message=msg, count=1)
        record_vendor_push_if_applicable('cortex_xdr', ok, msg)
    except Exception:
        pass
    return ok, msg


def _cortex_xdr_push_ioc_from_context_inner(ioc: dict[str, Any]) -> tuple[bool, str]:
    if not cortex_xdr_enabled():
        return True, 'disabled'
    if not isinstance(ioc, dict):
        return False, 'invalid_context'

    g = cortex_xdr_settings_dict()
    base = sanitize_cortex_base_url(g.get('cortex_xdr_base_url') or '')
    key_id = (g.get('cortex_xdr_api_key_id') or '').strip()
    api_key = (g.get('cortex_xdr_api_key') or '').strip()
    verify_ssl = (g.get('cortex_xdr_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')
    security_level = _normalize_security_level(g.get('cortex_xdr_security_level'))

    if not base or not key_id or not api_key:
        logger.warning('Cortex XDR push skipped: missing base URL or API credentials')
        return False, 'missing_config'

    root = _public_api_v1_root(base)
    action = (str(ioc.get('action') or 'create')).strip().lower()
    value = (str(ioc.get('value') or '')).strip()

    if action == 'remove':
        if not value:
            return False, 'remove_missing_value'
        ok, msg = _delete_indicator_by_value(
            root, key_id, api_key, verify_ssl, value, security_level=security_level,
        )
        if not ok:
            return ok, msg
        if _hash_blocklist_enabled(g) and (ioc.get('type') or '').strip() == 'Hash':
            hb_ok, hb_msg = _hash_blocklist_remove(
                root, key_id, api_key, verify_ssl, value, security_level=security_level,
            )
            if not hb_ok:
                logger.warning('Cortex XDR hash blocklist remove failed: %s', hb_msg)
                return False, f'{msg}; {hb_msg}'
            return True, f'{msg}; hash_blocklist_remove_ok'
        return ok, msg

    if action != 'create':
        return True, f'skip_action_{action}'

    rec = _ioc_to_tim_record(ioc)
    if rec is None:
        zt = (ioc.get('type') or '').strip()
        logger.info('Cortex XDR skip unsupported IOC type: %s', zt)
        return True, f'skip_unsupported_type_{zt or "unknown"}'

    ins_ok, ins_msg = _push_insert_jsons(
        root, key_id, api_key, verify_ssl, rec, value, security_level=security_level,
    )
    if not ins_ok:
        return False, ins_msg

    if _hash_blocklist_enabled(g) and (ioc.get('type') or '').strip() == 'Hash':
        hb_ok, hb_msg = _hash_blocklist_add(
            root, key_id, api_key, verify_ssl, ioc, value, security_level=security_level,
        )
        if not hb_ok:
            logger.warning('Cortex XDR hash blocklist add failed after successful insert: %s', hb_msg)
            return False, f'{ins_msg}; hash_blocklist: {hb_msg}'
        return True, f'{ins_msg}; hash_blocklist_ok'

    return True, ins_msg


def _validate_cortex_base_url(base: str) -> Optional[str]:
    """Return a user-facing error string, or None if the base URL looks acceptable."""
    b = sanitize_cortex_base_url(base)
    if not b:
        return 'Base URL is empty'
    if not b.lower().startswith('https://'):
        return 'Base URL must start with https:// (example: https://api-xx.paloaltonetworks.com)'
    try:
        parsed = urlparse(b)
    except Exception:
        return 'Base URL is not a valid URL'
    if not parsed.hostname:
        return 'Base URL is missing a hostname'
    host = parsed.hostname.lower()
    if host in ('localhost', '127.0.0.1'):
        return 'Base URL must be your Cortex XDR API host (api-*.paloaltonetworks.com), not localhost'
    return None


def cortex_xdr_test_connection(
    settings: Optional[dict[str, str]] = None,
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    """
    POST ``indicators/get`` (the documented IOC API also used by ``indicators/insert_jsons``)
    using either Standard or Advanced auth per ``cortex_xdr_security_level``.

    Returns ``{ success, steps: [{ step, status, message }] }`` for the admin UI.
    """
    try:
        return _cortex_xdr_test_connection_impl(settings, verify_ssl=verify_ssl)
    except Exception as e:
        logger.exception('cortex_xdr_test_connection failed')
        err_msg = str(e).strip() or type(e).__name__
        return {
            'success': False,
            'error_type': type(e).__name__,
            'steps': [
                {
                    'step': 'server',
                    'status': 'fail',
                    'message': f'Internal error during Cortex test: {type(e).__name__}: {err_msg}',
                },
            ],
        }


def _cortex_xdr_test_connection_impl(
    settings: Optional[dict[str, str]] = None,
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    g = settings or cortex_xdr_settings_dict()
    security_level = _normalize_security_level(g.get('cortex_xdr_security_level'))
    steps: list[dict[str, str]] = []
    steps.append({
        'step': 'ziochub',
        'status': 'ok',
        'message': (
            f'ZIoCHub accepted test request (security_level={security_level}); '
            f'next step POSTs to Cortex public_api ({_CORTEX_TEST_PROBE_SUBPATH}).'
        ),
    })

    raw_base = (g.get('cortex_xdr_base_url') or '').strip()
    base = sanitize_cortex_base_url(raw_base)
    key_id = (g.get('cortex_xdr_api_key_id') or '').strip()
    api_key = (g.get('cortex_xdr_api_key') or '').strip()

    if verify_ssl is None:
        verify_ssl = (g.get('cortex_xdr_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')

    missing = []
    if not base:
        missing.append('base_url')
    if not key_id:
        missing.append('api_key_id')
    if not api_key:
        missing.append('api_key_secret')
    if missing:
        hint = (
            'Fill Base URL, API key ID, and API key secret in the form (or Save first so the secret is stored). '
            'If the secret field is empty, Test uses the last saved secret from the database.'
        )
        steps.append({
            'step': 'config',
            'status': 'fail',
            'message': 'Missing required Cortex XDR settings: ' + ', '.join(missing) + '. ' + hint,
        })
        return {'success': False, 'steps': steps}

    if raw_base and base != raw_base.rstrip('/'):
        steps.append({
            'step': 'config',
            'status': 'ok',
            'message': f'Base URL normalized (removed spaces): {base}',
        })

    url_err = _validate_cortex_base_url(base)
    if url_err:
        steps.append({'step': 'config', 'status': 'fail', 'message': url_err})
        return {'success': False, 'steps': steps}

    url = _cortex_test_probe_url(base)
    # Empty filter set returns either the first page of indicators (200) or an empty objects list (200).
    payload = {'request_data': {}}
    hdrs = _sign_headers(key_id, api_key, tim_source=False, security_level=security_level)

    code, data, raw = _http_json_post(
        url, payload, hdrs, verify_ssl, timeout_sec=REQUEST_TIMEOUT_TEST_SEC
    )

    # Give the operator immediate context (helps debug "wrong host").
    steps.append({
        'step': 'request',
        'status': 'ok',
        'message': (
            f'POST {url} (verify_tls={bool(verify_ssl)}, '
            f'timeout={REQUEST_TIMEOUT_TEST_SEC}s, security_level={security_level})'
        ),
    })

    if 200 <= code < 300:
        # Surface object count when present so the operator sees that auth + IOC API actually worked.
        detail = ''
        if isinstance(data, dict):
            n = data.get('objects_count')
            if isinstance(n, int):
                detail = f' (objects_count={n})'
        steps.append({
            'step': 'cortex_api',
            'status': 'ok',
            'message': f'HTTP {code} on {_CORTEX_TEST_PROBE_SUBPATH} ({security_level} auth){detail}',
        })
        return {'success': True, 'steps': steps}

    if code == 401:
        if security_level == _SECURITY_LEVEL_ADVANCED:
            hint = (
                'Security level is set to Advanced but auth failed. Likely causes: (a) the key in Cortex '
                'was created as Standard - switch ZIoCHub to Standard; (b) wrong API key ID or secret; '
                '(c) server clock drift (run `timedatectl` on Linux - skew >30s breaks the signature).'
            )
        else:
            hint = (
                'Security level is set to Standard but auth failed. Likely causes: (a) the key in Cortex '
                'was created as Advanced - switch ZIoCHub to Advanced; (b) wrong API key ID or secret; '
                '(c) the key was revoked or expired in Cortex.'
            )
        msg = f'HTTP 401 - authentication failed. {hint} Response: {raw[:400]}'.strip()
        steps.append({'step': 'cortex_api', 'status': 'fail', 'message': msg})
        return {'success': False, 'steps': steps}

    if code == 403:
        # Authenticated but role lacks IOC permission. The same role is required in production for
        # ``indicators/insert_jsons``, so we surface this as a real failure rather than masking it.
        hint = (
            f'HTTP 403 - the key was authenticated but the role does not have IOC API permission. '
            f'In Cortex, edit this API key and assign a role with IOC management permissions '
            f'(e.g. Instance Admin or a custom role that includes "Manage IOCs").'
        )
        steps.append({'step': 'cortex_api', 'status': 'fail', 'message': f'{hint} Response: {raw[:300]}'})
        return {'success': False, 'steps': steps}

    if code == 0:
        hint = 'If this is TLS-related, try "Ignore TLS for this test" temporarily to confirm connectivity.'
        steps.append({'step': 'cortex_api', 'status': 'fail', 'message': f'Connection failed - {raw[:400]}. {hint}'.strip()})
        return {'success': False, 'steps': steps}

    hint = ' (check base URL host)' if code == 404 else ''
    snippet = raw[:400] + ('...' if len(raw) > 400 else '')
    steps.append({'step': 'cortex_api', 'status': 'fail', 'message': f'HTTP {code}{hint} - {snippet}'.strip()})
    return {'success': False, 'steps': steps}
