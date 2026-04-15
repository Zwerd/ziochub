"""
Palo Alto Cortex XDR — IOC outbound integration via the **public** REST API.

Admin fields live in ``system_settings`` under ``cortex_xdr_*`` (Integrations → Cortex XDR).

**Not the browser UI API:** the console path *Threat Management → Detection Rules → IOC* calls an internal
route such as ``/api/webapp/ioc/add_rule/`` with fields like ``RULE_INDICATOR`` / ``IOC_TYPE``. That
endpoint is tied to the web session and is **not** documented for automation.

**Supported automation (TIM / indicators):** the same indicators are pushed through the documented API
used by Palo Alto tooling, e.g. ``POST {base}/public_api/v1/indicators/tim_insert_jsons/`` with a JSON
body ``{"request_data": [<indicator objects>], "validate": true}``. Each object uses keys such as
``indicator``, ``type`` (``DOMAIN_NAME``, ``IP``, ``HASH``, ``PATH`` for URLs), ``severity``,
``reputation``, optional ``expiration_date`` (epoch ms, or ``-1`` for tenant default TTL), and
``comment``. See *Cortex XDR REST API — Insert Simple Indicators (JSON)* and the Cortex XSOAR
``XDR_iocs`` integration reference implementation.

**Create after revoke:** ZIoCHub revoke calls ``disable_iocs`` (indicator stays in TIM). Re-adding the same
value then hits *Indicator already exists* on insert. In that case we call ``enable_iocs`` with the same
indicator string so the rule becomes active again without requiring a full TIM delete. Metadata
(severity/comment) may remain as in XDR until changed there; ZIoCHub history remains the source of truth
for analyst context.

**File hash blocklist (Hash IOC only):** in addition to TIM, optionally call the documented
``POST {base}/public_api/v1/hash_exceptions/blocklist/`` with ``request_data.hash_list`` (see *Block List
Files* / Cortex XSOAR ``xdr-blocklist-files`` / ``CoreIRApiModule.blocklist_files``). Revoke calls
``hash_exceptions/blocklist/remove/``. This is separate from the browser-only
``/api/webapp/response/hash_exceptions_statuses`` flow.

**Authentication:** Advanced API keys use a signed ``Authorization`` header
``SHA256(api_key + nonce + timestamp)`` plus ``x-xdr-nonce`` and ``x-xdr-timestamp`` (see Cortex XDR
API getting-started / IR client examples). Indicator TIM calls also send ``x-iocs-source``; hash blocklist
uses standard signing only.

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
from typing import Any, Optional

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SEC = 45
_NONCE_LEN = 64

_CORTEX_AUTH_SETTINGS_SUFFIX = '/public_api/v1/authentication-settings/get/settings'

# ZIoCHub IOC type → Cortex TIM ``type`` (UI uses IOC_TYPE e.g. DOMAIN_NAME; API uses the same strings).
_IOC_TYPE_MAP: dict[str, str] = {
    'Domain': 'DOMAIN_NAME',
    'IP': 'IP',
    'URL': 'PATH',
    'Hash': 'HASH',
}

_DEFAULT_SEVERITY = 'HIGH'
_DEFAULT_REPUTATION = 'BAD'
_ALLOWED_SEVERITY = frozenset({'INFO', 'INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'})
_ALLOWED_REPUTATION = frozenset({'GOOD', 'SUSPICIOUS', 'BAD', 'UNKNOWN'})


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
    )
    return {k: _get_setting(k, '') for k in keys}


def _hash_blocklist_enabled(g: dict[str, str]) -> bool:
    raw = (g.get('cortex_xdr_hash_blocklist_enabled') or 'true').strip().lower()
    return raw in ('true', '1', 'yes')


def _public_api_v1_root(base_url: str) -> str:
    b = (base_url or '').strip().rstrip('/')
    suf = '/public_api/v1'
    if b.endswith(suf):
        return b
    idx = b.find(suf + '/')
    if idx >= 0:
        return b[: idx + len(suf)]
    if b.endswith('/public_api'):
        return b + '/v1'
    return b + suf


def _cortex_auth_settings_url(base_url: str) -> str:
    root = _public_api_v1_root(base_url)
    return root + '/authentication-settings/get/settings'


def _indicators_url(root_v1: str, suffix: str) -> str:
    s = suffix.lstrip('/')
    return root_v1.rstrip('/') + '/indicators/' + s


def _post_tim(
    root_v1: str,
    api_key_id: str,
    api_key: str,
    verify_ssl: bool,
    path_suffix: str,
    body: dict[str, Any],
) -> tuple[int, Optional[dict[str, Any]], str]:
    url = _indicators_url(root_v1, path_suffix)
    hdrs = _sign_headers(api_key_id, api_key, tim_source=True)
    return _http_json_post(url, body, hdrs, verify_ssl)


def _post_v1(
    root_v1: str,
    api_key_id: str,
    api_key: str,
    verify_ssl: bool,
    subpath: str,
    body: dict[str, Any],
) -> tuple[int, Optional[dict[str, Any]], str]:
    """POST under ``/public_api/v1/<subpath>`` with signed auth (no ``x-iocs-source``)."""
    url = root_v1.rstrip('/') + '/' + subpath.lstrip('/')
    hdrs = _sign_headers(api_key_id, api_key, tim_source=False)
    return _http_json_post(url, body, hdrs, verify_ssl)


def _sign_headers(api_key_id: str, api_key: str, *, tim_source: bool) -> dict[str, str]:
    nonce = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(_NONCE_LEN))
    ts = str(int(datetime.now(timezone.utc).timestamp() * 1000))
    digest = hashlib.sha256(f'{api_key}{nonce}{ts}'.encode('utf-8')).hexdigest()
    h: dict[str, str] = {
        'x-xdr-timestamp': ts,
        'x-xdr-nonce': nonce,
        'x-xdr-auth-id': str(api_key_id),
        'Authorization': digest,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    if tim_source:
        h['x-iocs-source'] = 'ziochub'
    return h


def _http_json_post(url: str, body: dict[str, Any], headers: dict[str, str], verify_ssl: bool) -> tuple[int, Optional[dict[str, Any]], str]:
    raw = json.dumps(body, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(url, data=raw, method='POST')
    for k, v in headers.items():
        req.add_header(k, v)
    ctx = _ssl_context(verify_ssl)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC, context=ctx) as resp:
            code = resp.getcode()
            txt = resp.read().decode('utf-8', errors='replace')
            try:
                return code, json.loads(txt) if txt.strip() else {}, ''
            except json.JSONDecodeError:
                return code, None, txt[:500]
    except urllib.error.HTTPError as e:
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


def _tim_comment_from_context(ioc: dict[str, Any]) -> str:
    parts: list[str] = []
    tid = (ioc.get('ticket_id') or '').strip()
    if tid:
        parts.append(f'ticket={tid}')
    an = (ioc.get('analyst') or '').strip()
    if an:
        parts.append(f'analyst={an}')
    cm = (ioc.get('comment') or '').strip()
    if cm:
        parts.append(cm)
    out = ' | '.join(parts) if parts else 'ZIoCHub IOC'
    return out[:4000]


def _ioc_to_tim_record(ioc: dict[str, Any]) -> Optional[dict[str, Any]]:
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
        'comment': _tim_comment_from_context(ioc),
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
    """True if Cortex response suggests the indicator row already exists (e.g. after prior ``disable_iocs``)."""
    parts: list[str] = [(raw or '').lower()]
    if isinstance(data, dict):
        try:
            parts.append(json.dumps(data, ensure_ascii=False).lower())
        except (TypeError, ValueError):
            pass
    blob = ' '.join(parts)
    for needle in ('already exist', 'indicator already', 'ioc already exists'):
        if needle in blob:
            return True
    return False


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


def _push_tim_create(
    root: str,
    key_id: str,
    api_key: str,
    verify_ssl: bool,
    rec: dict[str, Any],
    value: str,
) -> tuple[bool, str]:
    """TIM insert + optional ``enable_iocs`` when the indicator already exists."""
    code, data, raw = _post_tim(
        root,
        key_id,
        api_key,
        verify_ssl,
        'tim_insert_jsons/',
        {'request_data': [rec], 'validate': True},
    )
    if code is not None and not (200 <= code < 300):
        if _looks_like_indicator_already_exists(data, raw):
            ecode, edata, eraw = _post_tim(root, key_id, api_key, verify_ssl, 'enable_iocs', {'request_data': [value]})
            if ecode is not None and 200 <= ecode < 300:
                en_ok, en_msg = _interpret_tim_reply(edata, op='enable_iocs')
                if en_ok:
                    logger.info(
                        'Cortex XDR: tim_insert_jsons HTTP %s (indicator exists); enable_iocs succeeded for %r',
                        code,
                        value[:128],
                    )
                    return True, f'enable_iocs_ok (after insert HTTP {code}: existing indicator)'
                return False, f'tim_insert_jsons HTTP {code}: {raw[:240]}; enable_iocs: {en_msg}'
            return False, f'tim_insert_jsons HTTP {code}: {raw[:240]}; enable_iocs HTTP {ecode}: {eraw[:200]}'
        return False, f'tim_insert_jsons HTTP {code}: {raw[:240]}'
    ok, msg = _interpret_tim_reply(data, op='tim_insert_jsons')
    if ok:
        return True, msg
    if _looks_like_indicator_already_exists(data, raw):
        ecode, edata, eraw = _post_tim(root, key_id, api_key, verify_ssl, 'enable_iocs', {'request_data': [value]})
        en_msg = ''
        if ecode is not None and 200 <= ecode < 300:
            en_ok, en_msg = _interpret_tim_reply(edata, op='enable_iocs')
            if en_ok:
                logger.info(
                    'Cortex XDR: tim_insert_jsons conflict %r; enable_iocs succeeded',
                    msg[:200],
                )
                return True, f'enable_iocs_ok (after tim_insert_jsons: {msg[:400]})'
        logger.warning(
            'Cortex XDR: tim_insert_jsons failed (%s) and enable_iocs fallback failed: HTTP %s %s',
            msg,
            ecode,
            eraw[:200],
        )
        if ecode is not None and 200 <= ecode < 300:
            return False, f'{msg}; enable_iocs: {en_msg or eraw[:200]}'
        return False, f'{msg}; enable_iocs: HTTP {ecode} {eraw[:200]}'
    logger.warning('Cortex XDR tim_insert_jsons failed: %s', msg)
    return False, msg


def _hash_blocklist_add(
    root: str,
    key_id: str,
    api_key: str,
    verify_ssl: bool,
    ioc: dict[str, Any],
    hash_value: str,
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
) -> tuple[bool, str]:
    inner = {'hash_list': [_normalize_hash_value(hash_value)]}
    code, data, raw = _post_v1(
        root,
        key_id,
        api_key,
        verify_ssl,
        'hash_exceptions/blocklist/remove/',
        {'request_data': inner},
    )
    if code is None or not (200 <= code < 300):
        return False, f'hash_blocklist_remove HTTP {code}: {raw[:300]}'
    return _interpret_hash_exception_reply(data, 'hash_blocklist_remove')


def cortex_xdr_push_ioc_from_context(ioc: dict[str, Any]) -> tuple[bool, str]:
    """
    Push one IOC event: TIM (``tim_insert_jsons`` / ``enable_iocs`` / ``disable_iocs``) and, for **Hash** only,
    optional Action Center **blocklist** via ``hash_exceptions/blocklist`` (and remove on revoke).

    ``Email`` IOCs are skipped for TIM (no mapped type). Hash blocklist still applies only when type is Hash.
    """
    if not cortex_xdr_enabled():
        return True, 'disabled'
    if not isinstance(ioc, dict):
        return False, 'invalid_context'

    g = cortex_xdr_settings_dict()
    base = (g.get('cortex_xdr_base_url') or '').strip()
    key_id = (g.get('cortex_xdr_api_key_id') or '').strip()
    api_key = (g.get('cortex_xdr_api_key') or '').strip()
    verify_ssl = (g.get('cortex_xdr_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')

    if not base or not key_id or not api_key:
        logger.warning('Cortex XDR push skipped: missing base URL or API credentials')
        return False, 'missing_config'

    root = _public_api_v1_root(base)
    action = (str(ioc.get('action') or 'create')).strip().lower()
    value = (str(ioc.get('value') or '')).strip()

    if action == 'remove':
        if not value:
            return False, 'remove_missing_value'
        code, data, raw = _post_tim(root, key_id, api_key, verify_ssl, 'disable_iocs', {'request_data': [value]})
        if code is not None and not (200 <= code < 300):
            return False, f'disable_iocs HTTP {code}: {raw[:240]}'
        ok, msg = _interpret_tim_reply(data, op='disable_iocs')
        if not ok:
            logger.warning('Cortex XDR disable_iocs failed: %s', msg)
            return ok, msg
        if _hash_blocklist_enabled(g) and (ioc.get('type') or '').strip() == 'Hash':
            hb_ok, hb_msg = _hash_blocklist_remove(root, key_id, api_key, verify_ssl, value)
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

    tim_ok, tim_msg = _push_tim_create(root, key_id, api_key, verify_ssl, rec, value)
    if not tim_ok:
        return False, tim_msg

    if _hash_blocklist_enabled(g) and (ioc.get('type') or '').strip() == 'Hash':
        hb_ok, hb_msg = _hash_blocklist_add(root, key_id, api_key, verify_ssl, ioc, value)
        if not hb_ok:
            logger.warning('Cortex XDR hash blocklist add failed after successful TIM: %s', hb_msg)
            return False, f'{tim_msg}; hash_blocklist: {hb_msg}'
        return True, f'{tim_msg}; hash_blocklist_ok'

    return True, tim_msg


def cortex_xdr_test_connection(
    settings: Optional[dict[str, str]] = None,
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    """
    POST ``authentication-settings/get/settings`` with **signed** API key headers.

    Returns ``{ success, steps: [{ step, status, message }] }`` for the admin UI.
    HTTP 403 after TLS + auth is treated as reachable (role may block this probe).
    """
    g = settings or cortex_xdr_settings_dict()
    steps: list[dict[str, str]] = []

    base = (g.get('cortex_xdr_base_url') or '').strip()
    key_id = (g.get('cortex_xdr_api_key_id') or '').strip()
    api_key = (g.get('cortex_xdr_api_key') or '').strip()

    if verify_ssl is None:
        verify_ssl = (g.get('cortex_xdr_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')

    if not base:
        steps.append({'step': 'config', 'status': 'fail', 'message': 'cortex_xdr_base_url is empty'})
        return {'success': False, 'steps': steps}
    if not key_id or not api_key:
        steps.append({'step': 'config', 'status': 'fail', 'message': 'API key ID and API key secret are required'})
        return {'success': False, 'steps': steps}

    url = _cortex_auth_settings_url(base)
    payload = {'request_data': {}}
    hdrs = _sign_headers(key_id, api_key, tim_source=False)

    code, data, raw = _http_json_post(url, payload, hdrs, verify_ssl)

    if 200 <= code < 300:
        steps.append({'step': 'cortex_api', 'status': 'ok', 'message': f'HTTP {code} on authentication-settings (signed auth)'})
        return {'success': True, 'steps': steps}

    if code == 401:
        msg = (
            f'HTTP 401 — invalid API key ID/secret, or clock skew. '
            f'Ensure the key is an Advanced API key and base URL is https://api-{{tenant}}.paloaltonetworks.com. {raw[:180]}'
        ).strip()
        steps.append({'step': 'cortex_api', 'status': 'fail', 'message': msg})
        return {'success': False, 'steps': steps}

    if code == 403:
        msg = (
            f'HTTP 403 — reachable; this probe may require higher RBAC on the API key. {raw[:180]}'
        ).strip()
        steps.append({'step': 'cortex_api', 'status': 'ok', 'message': msg})
        return {'success': True, 'steps': steps}

    hint = ' (check base URL host)' if code == 404 else ''
    snippet = raw[:200] + ('…' if len(raw) > 200 else '')
    steps.append({'step': 'cortex_api', 'status': 'fail', 'message': f'HTTP {code}{hint} — {snippet}'.strip()})
    return {'success': False, 'steps': steps}
