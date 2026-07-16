"""
``utils.cisco_esa`` — Cisco Secure Email Gateway (ESA / AsyncOS) dictionary sync via REST API.

Auth:
- ``POST {base}/login`` — session JWT (reporting/UI); used only for the admin "login" test step.
- **Configuration APIs** (dictionaries add/remove): ``Authorization: Basic`` with plain username:passphrase
  (Cisco Secure Email API Guide — Basic auth or client-credentials JWT; login JWT is not accepted on many clusters).

Paths (v2.0, Cisco Secure Email API Guide): POST/DELETE
``config/dictionaries/<dictionary_name>/words?device_type=esa`` (cluster adds ``&mode=cluster``, etc.).

- **POST add:** ``{"data":{"words":[["term1"],["term2"],...]}}``-each term is a list (optional weight/prefix).
- **DELETE:** ``{"data":{"words":["term1","term2",...]}}``-flat string array (per Cisco docs; not nested lists).

Multiple IOCs per dictionary are batched into one POST/DELETE per dictionary (Basic auth).

Mappings (system_settings ``esa_mappings``): JSON array of
``{"dictionary_name": "<as on ESA>", "ioc_type": "Email"|"Domain"|"IP"|"URL"}``-one IOC type per row.

Used after IOC create (background), on manual revoke, and from cleaner.py before deleting expired rows.
"""
from __future__ import annotations

import base64
import json
import logging
import threading
import time
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

# Canonical test IOC per type (normalized before push — same as production).
ESA_TEST_IOC_RAW: dict[str, str] = {
    'Email': 'TEST@EXAMPLE.COM',
    'Domain': 'EXAMPLE.COM',
    'IP': '203.0.113.99',
    'URL': 'https://example.com/ziochub-test',
}

ESA_TEST_VERIFY_RETRIES = 3
ESA_TEST_VERIFY_DELAY_SEC = 1.0


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


def _esa_basic_auth_header(username: str, passphrase: str) -> str:
    """RFC 7617 Basic auth for Configuration APIs (username:passphrase, not login JSON encoding)."""
    cred = f'{(username or "").strip()}:{(passphrase or "").strip()}'.encode('utf-8')
    return 'Basic ' + base64.b64encode(cred).decode('ascii')


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
    method: str,
    path_pattern: str,
    body: Optional[bytes],
    verify_ssl: bool,
    *,
    username: str,
    passphrase: str,
) -> tuple[bool, str]:
    base = _base_url_normalize(base_url)
    rel = (path_pattern or '').strip().lstrip('/')
    if not rel:
        return False, 'Path pattern is empty'
    if '{dictionary}' in rel:
        return False, 'Path still contains {dictionary} placeholder (internal error)'
    u = (username or '').strip()
    p = (passphrase or '').strip()
    if not u or not p:
        return False, 'esa_username or esa_passphrase is empty'
    url = f'{base}/{rel}'
    m = (method or 'POST').strip().upper()
    ctx = _ssl_context(verify_ssl)
    if m in ('GET', 'HEAD'):
        data = None
    else:
        data = body
    req = urllib.request.Request(url, data=data, method=m)
    apply_user_agent_to_request(req)
    req.add_header('Authorization', _esa_basic_auth_header(u, p))
    req.add_header('Accept', '*/*')
    req.add_header('cache-control', 'no-cache')
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
    """One POST per dictionary with all words (Basic auth per Cisco Configuration API guide)."""
    g = settings or esa_settings_dict()
    if g.get('esa_enabled', '').strip().lower() not in ('true', '1', 'yes'):
        return True, 'skipped (disabled)'
    base = g.get('esa_base_url', '').strip()
    user = g.get('esa_username', '').strip()
    pw = g.get('esa_passphrase', '').strip()
    verify_ssl = g.get('esa_verify_ssl', 'true').strip().lower() in ('true', '1', 'yes')
    if not by_dictionary:
        return True, 'nothing to add'
    if not base or not user or not pw:
        return False, 'esa_base_url, esa_username, or esa_passphrase is empty'
    all_ok = True
    last_msg = ''
    for dname in sorted(by_dictionary.keys()):
        words = sorted(w for w in by_dictionary[dname] if w)
        if not words:
            continue
        path = _dictionary_words_path(dname, g)
        body = _esa_words_add_body(words)
        ok, msg = esa_api_call(base, 'POST', path, body, verify_ssl, username=user, passphrase=pw)
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
    """One DELETE per dictionary with all words (Basic auth per Cisco Configuration API guide)."""
    g = settings or esa_settings_dict()
    if g.get('esa_enabled', '').strip().lower() not in ('true', '1', 'yes'):
        return True, 'skipped (disabled)'
    base = g.get('esa_base_url', '').strip()
    user = g.get('esa_username', '').strip()
    pw = g.get('esa_passphrase', '').strip()
    verify_ssl = g.get('esa_verify_ssl', 'true').strip().lower() in ('true', '1', 'yes')
    if not by_dictionary:
        return True, 'nothing to remove'
    if not base or not user or not pw:
        return False, 'esa_base_url, esa_username, or esa_passphrase is empty'
    all_ok = True
    last_msg = ''
    for dname in sorted(by_dictionary.keys()):
        words = sorted(w for w in by_dictionary[dname] if w)
        if not words:
            continue
        path = _dictionary_words_path(dname, g)
        body = _esa_words_delete_body(words)
        ok, msg = esa_api_call(base, 'DELETE', path, body, verify_ssl, username=user, passphrase=pw)
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


def _esa_http_error_detail(body: str) -> str:
    """Extract Cisco AsyncOS error message from JSON body for UI/logs."""
    raw = (body or '').strip()
    if not raw:
        return ''
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            err = data.get('error')
            if isinstance(err, dict):
                parts = [
                    str(err.get('message') or '').strip(),
                    str(err.get('explanation') or '').strip(),
                ]
                detail = ' — '.join(p for p in parts if p)
                if detail:
                    return detail[:500]
    except (TypeError, ValueError):
        pass
    return raw.replace('\n', ' ')[:500]


def _esa_response_preview(body: str, limit: int = 1200) -> str:
    text = (body or '').strip()
    if not text:
        return '(empty body)'
    return text[:limit] + ('…' if len(text) > limit else '')


def _esa_config_http_request(
    method: str,
    url: str,
    verify_ssl: bool,
    username: str,
    passphrase: str,
    *,
    body: Optional[bytes] = None,
) -> tuple[int, str]:
    """Configuration API call with Basic auth. Returns (http_code, response_body_text)."""
    m = (method or 'GET').strip().upper()
    ctx = _ssl_context(verify_ssl)
    data = None if m in ('GET', 'HEAD') else body
    req = urllib.request.Request(url, data=data, method=m)
    apply_user_agent_to_request(req)
    req.add_header('Authorization', _esa_basic_auth_header(username, passphrase))
    req.add_header('Accept', '*/*')
    req.add_header('cache-control', 'no-cache')
    if body is not None and m not in ('GET', 'HEAD'):
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC, context=ctx) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            return resp.getcode(), raw
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode('utf-8', errors='replace')
        except Exception:
            raw = ''
        return int(e.code), raw
    except urllib.error.URLError as e:
        return 0, str(e.reason or e)
    except Exception as e:
        return 0, str(e)


def esa_test_ioc_value(ioc_type: str) -> str:
    """Return normalized test IOC string for ESA dictionary E2E test."""
    t = canonical_esa_ioc_type(ioc_type) or ''
    raw = ESA_TEST_IOC_RAW.get(t, 'ziochub-test.example')
    return normalize_dictionary_word(t, raw)


def _esa_extract_word_terms_from_body(body: str) -> set[str]:
    """Parse word terms from GET config/dictionaries/.../words (or embedded list) JSON."""
    terms: set[str] = set()
    try:
        parsed = json.loads(body) if body else {}
    except (TypeError, ValueError):
        return terms
    if not isinstance(parsed, dict):
        return terms

    def _collect(words_obj) -> None:
        if not isinstance(words_obj, list):
            return
        for entry in words_obj:
            if isinstance(entry, list) and entry:
                term = str(entry[0]).strip()
                if term:
                    terms.add(term)
            elif isinstance(entry, str) and entry.strip():
                terms.add(entry.strip())

    data = parsed.get('data')
    if isinstance(data, dict) and 'words' in data:
        _collect(data.get('words'))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and 'words' in item:
                _collect(item.get('words'))
    return terms


def _esa_normalized_terms_in_body(body: str, ioc_type: str) -> set[str]:
    return {normalize_dictionary_word(ioc_type, t) for t in _esa_extract_word_terms_from_body(body)}


def _esa_append_http_trace(
    http_trace: list[dict[str, Any]],
    *,
    label: str,
    method: str,
    url: str,
    http_code: int,
    body: str,
    purpose: str = '',
    extra: Optional[dict[str, Any]] = None,
) -> None:
    entry: dict[str, Any] = {
        'label': label,
        'purpose': purpose,
        'method': method,
        'url': url,
        'auth': 'Authorization: Basic',
        'http_code': http_code,
        'ok': 200 <= http_code < 300,
        'response_preview': _esa_response_preview(body),
        'error_detail': _esa_http_error_detail(body) if (http_code >= 400 or http_code == 0) else None,
    }
    if extra:
        entry.update(extra)
    http_trace.append(entry)


def _esa_get_dictionary_words(
    words_url: str,
    ioc_type: str,
    verify_ssl: bool,
    username: str,
    passphrase: str,
    http_trace: list[dict[str, Any]],
    trace_label: str,
) -> tuple[int, set[str], str]:
    code, body = _esa_config_http_request('GET', words_url, verify_ssl, username, passphrase)
    terms = _esa_normalized_terms_in_body(body, ioc_type) if 200 <= code < 300 else set()
    _esa_append_http_trace(
        http_trace,
        label=trace_label,
        method='GET',
        url=words_url,
        http_code=code,
        body=body,
        purpose='Read dictionary words list',
        extra={'terms_normalized': sorted(terms)[:50]},
    )
    return code, terms, body


def _esa_verify_word_state(
    words_url: str,
    test_word: str,
    ioc_type: str,
    verify_ssl: bool,
    username: str,
    passphrase: str,
    http_trace: list[dict[str, Any]],
    step_prefix: str,
    *,
    expect_present: bool,
) -> tuple[bool, str]:
    """Poll GET words until test_word presence matches expect_present (cluster propagation)."""
    want = 'present' if expect_present else 'absent'
    last_terms: set[str] = set()
    last_code = 0
    last_detail = ''
    for attempt in range(ESA_TEST_VERIFY_RETRIES):
        trace_label = f'{step_prefix}:verify_{"add" if expect_present else "delete"}'
        if attempt:
            trace_label += f':retry{attempt + 1}'
        last_code, last_terms, body = _esa_get_dictionary_words(
            words_url, ioc_type, verify_ssl, username, passphrase, http_trace, trace_label,
        )
        if not (200 <= last_code < 300):
            last_detail = _esa_http_error_detail(body) or f'HTTP {last_code}'
            if attempt + 1 < ESA_TEST_VERIFY_RETRIES:
                time.sleep(ESA_TEST_VERIFY_DELAY_SEC)
            continue
        present = test_word in last_terms
        if present == expect_present:
            if expect_present:
                return True, f'GET words: found "{test_word}" in dictionary'
            return True, f'GET words: "{test_word}" not in dictionary (removed)'
        if attempt + 1 < ESA_TEST_VERIFY_RETRIES:
            time.sleep(ESA_TEST_VERIFY_DELAY_SEC)
    if expect_present:
        sample = ', '.join(sorted(last_terms)[:8])
        return False, f'GET words: "{test_word}" not found after {ESA_TEST_VERIFY_RETRIES} tries (HTTP {last_code}; sample: {sample or "empty"})'
    sample = ', '.join(sorted(last_terms)[:8])
    return False, f'GET words: "{test_word}" still present after {ESA_TEST_VERIFY_RETRIES} tries (HTTP {last_code}; sample: {sample or "empty"})'


def _esa_dictionary_e2e_test(
    settings: dict[str, str],
    *,
    dictionary_name: str,
    ioc_type: str,
    base: str,
    username: str,
    passphrase: str,
    verify_ssl: bool,
    steps: list[dict[str, str]],
    http_trace: list[dict[str, Any]],
    e2e_log: list[dict[str, Any]],
) -> bool:
    """Add test IOC → verify in dict → delete → verify removed (one mapped dictionary)."""
    test_word = esa_test_ioc_value(ioc_type)
    step_prefix = f'dict:{dictionary_name}'
    rel = _dictionary_words_path(dictionary_name, settings)
    words_url = f'{_base_url_normalize(base)}/{rel}'
    log_entry: dict[str, Any] = {
        'dictionary_name': dictionary_name,
        'ioc_type': ioc_type,
        'test_ioc_raw': ESA_TEST_IOC_RAW.get(canonical_esa_ioc_type(ioc_type) or '', ''),
        'test_ioc_normalized': test_word,
        'operations': [],
    }
    e2e_log.append(log_entry)
    all_ok = True

    def _op(name: str, ok: bool, message: str, http_code: Optional[int] = None) -> None:
        nonlocal all_ok
        if not ok:
            all_ok = False
        log_entry['operations'].append({
            'operation': name,
            'ok': ok,
            'message': message,
            'http_code': http_code,
        })
        steps.append({
            'step': f'{step_prefix}:{name}',
            'status': 'ok' if ok else 'fail',
            'message': message,
        })

    # 1) POST add
    add_body = _esa_words_add_body([test_word])
    code, body = _esa_config_http_request(
        'POST', words_url, verify_ssl, username, passphrase, body=add_body,
    )
    _esa_append_http_trace(
        http_trace,
        label=f'{step_prefix}:add',
        method='POST',
        url=words_url,
        http_code=code,
        body=body,
        purpose=f'Add test IOC {test_word!r}',
        extra={'request_body': add_body.decode('utf-8')},
    )
    add_ok = 200 <= code < 300
    add_msg = f'POST add "{test_word}" → HTTP {code}'
    if not add_ok:
        detail = _esa_http_error_detail(body)
        if detail:
            add_msg = f'{add_msg}: {detail}'
    _op('add', add_ok, add_msg, code)
    if not add_ok:
        return False

    # 2) GET verify present
    verify_ok, verify_msg = _esa_verify_word_state(
        words_url, test_word, ioc_type, verify_ssl, username, passphrase,
        http_trace, step_prefix, expect_present=True,
    )
    _op('verify_add', verify_ok, verify_msg)
    if not verify_ok:
        # Best-effort cleanup
        del_body = _esa_words_delete_body([test_word])
        _esa_config_http_request('DELETE', words_url, verify_ssl, username, passphrase, body=del_body)
        return False

    # 3) DELETE remove
    del_body = _esa_words_delete_body([test_word])
    code, body = _esa_config_http_request(
        'DELETE', words_url, verify_ssl, username, passphrase, body=del_body,
    )
    _esa_append_http_trace(
        http_trace,
        label=f'{step_prefix}:delete',
        method='DELETE',
        url=words_url,
        http_code=code,
        body=body,
        purpose=f'Remove test IOC {test_word!r}',
        extra={'request_body': del_body.decode('utf-8')},
    )
    del_ok = 200 <= code < 300 or code in (404, 410)
    del_msg = f'DELETE remove "{test_word}" → HTTP {code}'
    if not del_ok:
        detail = _esa_http_error_detail(body)
        if detail:
            del_msg = f'{del_msg}: {detail}'
    _op('delete', del_ok, del_msg, code)
    if not del_ok:
        return False

    # 4) GET verify absent
    verify_del_ok, verify_del_msg = _esa_verify_word_state(
        words_url, test_word, ioc_type, verify_ssl, username, passphrase,
        http_trace, step_prefix, expect_present=False,
    )
    _op('verify_delete', verify_del_ok, verify_del_msg)
    return all_ok and verify_del_ok


def _esa_push_operation_debug(settings: dict[str, str]) -> dict[str, Any]:
    """Document exact ZIoCHub push paths (add/remove words on existing dictionaries)."""
    qs = esa_config_query_string(settings)
    mappings = parse_mappings(settings.get('esa_mappings', '[]'))
    base = _base_url_normalize(settings.get('esa_base_url', ''))
    push_paths: list[dict[str, str]] = []
    for row in mappings[:8]:
        dname = row.get('dictionary_name') or ''
        ioc_t = row.get('ioc_type') or ''
        if not dname:
            continue
        rel = _dictionary_words_path(dname, settings)
        sample_word = esa_test_ioc_value(ioc_t)
        push_paths.append({
            'dictionary_name': dname,
            'ioc_type': ioc_t,
            'test_ioc': sample_word,
            'add_method': 'POST',
            'add_url': f'{base}/{rel}' if base else rel,
            'add_body_example': _esa_words_add_body([sample_word]).decode('utf-8'),
            'remove_method': 'DELETE',
            'remove_url': f'{base}/{rel}' if base else rel,
            'remove_body_example': _esa_words_delete_body([sample_word]).decode('utf-8'),
        })
    return {
        'scope': 'E2E test per mapping: POST add → GET verify → DELETE → GET verify absent.',
        'query_string': qs,
        'test_ioc_by_type': {t: esa_test_ioc_value(t) for t in ESA_IOC_TYPES},
        'mapped_dictionaries': [{'dictionary_name': r['dictionary_name'], 'ioc_type': r['ioc_type']} for r in mappings],
        'push_paths': push_paths,
    }


def _esa_log_test_debug(summary: str, debug: dict[str, Any]) -> None:
    """Always log full ESA test trace (sanitized — no passphrase)."""
    logger.info('ESA test: %s', summary)
    try:
        payload = json.dumps(debug, ensure_ascii=False, default=str)
        if len(payload) > 12000:
            payload = payload[:12000] + '…(truncated)'
        logger.info('ESA test DEBUG: %s', payload)
    except Exception:
        logger.info('ESA test DEBUG (fallback): %r', debug)


def esa_test_connection(settings: Optional[dict[str, str]] = None) -> dict[str, Any]:
    """Return { success, steps, debug } for admin UI. Debug is always populated on test."""
    g = settings or esa_settings_dict()
    steps: list[dict[str, str]] = []
    http_trace: list[dict[str, Any]] = []
    base = g.get('esa_base_url', '').strip()
    user = g.get('esa_username', '').strip()
    pw = g.get('esa_passphrase', '').strip()
    verify_ssl = g.get('esa_verify_ssl', 'true').strip().lower() in ('true', '1', 'yes')
    mode = (g.get('esa_deployment_mode') or 'standalone').strip().lower()
    qs = esa_config_query_string(g)
    push_debug = _esa_push_operation_debug(g)
    debug: dict[str, Any] = {
        'auth_note': (
            'Admin in ESA web UI ≠ automatic Config API auth. '
            'ZIoCHub uses Authorization: Basic for dictionary APIs (Cisco p.92–93). '
            '/login JWT is tested separately (reporting/session only).'
        ),
        'settings': {
            'base_url': base,
            'username': user,
            'deployment_mode': mode,
            'query_string': qs,
            'verify_ssl': verify_ssl,
            'group_name': (g.get('esa_group_name') or '').strip() or None,
            'host_name': (g.get('esa_host_name') or '').strip() or None,
        },
        'ziochub_push': push_debug,
        'dictionary_e2e': [],
        'http_trace': http_trace,
    }

    def _finish(success: bool) -> dict[str, Any]:
        summary = 'ok' if success else 'failed'
        _esa_log_test_debug(summary, debug)
        return {'success': success, 'steps': steps, 'debug': debug}

    if not base:
        steps.append({'step': 'config', 'status': 'fail', 'message': 'esa_base_url is empty'})
        return _finish(False)

    login_url = f'{_base_url_normalize(base)}/login'
    jwt, err = esa_login(base, user, pw, verify_ssl)
    http_trace.append({
        'label': 'login',
        'purpose': 'Reporting/session API sanity check (not used for dictionary push)',
        'method': 'POST',
        'url': login_url,
        'auth': 'JSON body: Base64(userName), Base64(passphrase)',
        'http_code': 200 if jwt else None,
        'ok': bool(jwt),
        'error': err or None,
        'jwt_length': len(jwt) if jwt else 0,
    })
    if not jwt:
        steps.append({'step': 'login', 'status': 'fail', 'message': err or 'failed'})
        return _finish(False)
    steps.append({'step': 'login', 'status': 'ok', 'message': 'JWT obtained (reporting/session — not used for dictionary push)'})

    probe_url = f'{_base_url_normalize(base)}/config/dictionaries?{qs}'
    code, body = _esa_config_http_request('GET', probe_url, verify_ssl, user, pw)
    http_trace.append({
        'label': 'list_dictionaries',
        'purpose': 'Config API probe — same auth as IOC push (Basic)',
        'method': 'GET',
        'url': probe_url,
        'auth': 'Authorization: Basic',
        'http_code': code,
        'ok': 200 <= code < 300,
        'response_preview': _esa_response_preview(body),
        'error_detail': _esa_http_error_detail(body) if code >= 400 else None,
    })
    if 200 <= code < 300:
        dict_names: list[str] = []
        try:
            parsed = json.loads(body) if body else {}
            data = parsed.get('data') if isinstance(parsed, dict) else None
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get('name'):
                        dict_names.append(str(item['name']))
            elif isinstance(data, dict):
                dict_names = list(data.keys())
        except (TypeError, ValueError):
            pass
        if dict_names:
            debug['dictionaries_on_appliance'] = dict_names[:30]
        steps.append({
            'step': 'dictionaries',
            'status': 'ok',
            'message': f'HTTP {code} via Basic auth (?{qs})',
        })

        mappings = parse_mappings(g.get('esa_mappings', '[]'))
        if not mappings:
            steps.append({
                'step': 'dictionary_e2e',
                'status': 'fail',
                'message': 'No esa_mappings configured — add dictionary rows (name + IOC type) to run add/verify/delete test',
            })
            return _finish(False)

        e2e_log: list[dict[str, Any]] = debug['dictionary_e2e']
        e2e_all_ok = True
        for row in mappings:
            dname = (row.get('dictionary_name') or '').strip()
            ioc_t = row.get('ioc_type') or ''
            if not dname or not ioc_t:
                continue
            ok = _esa_dictionary_e2e_test(
                g,
                dictionary_name=dname,
                ioc_type=ioc_t,
                base=base,
                username=user,
                passphrase=pw,
                verify_ssl=verify_ssl,
                steps=steps,
                http_trace=http_trace,
                e2e_log=e2e_log,
            )
            if not ok:
                e2e_all_ok = False

        if e2e_all_ok:
            steps.append({
                'step': 'dictionary_e2e',
                'status': 'ok',
                'message': f'All {len(e2e_log)} mapped dictionary(s): add → verify → delete → verify removed',
            })
        else:
            steps.append({
                'step': 'dictionary_e2e',
                'status': 'fail',
                'message': 'One or more dictionary E2E tests failed — see steps dict:<name>:add|verify_add|delete|verify_delete',
            })
        return _finish(e2e_all_ok)

    detail = _esa_http_error_detail(body)
    msg = f'HTTP {code}'
    if detail:
        msg = f'{msg}: {detail}'
    msg = f'{msg} (?{qs})'
    steps.append({'step': 'dictionaries', 'status': 'fail', 'message': msg})
    if code == 401:
        steps.append({
            'step': 'hint',
            'status': 'fail',
            'message': (
                '401 on Config API with valid /login usually means wrong auth method was used previously '
                '(login JWT vs Basic). Current test uses Basic. See debug.http_trace and journalctl '
                '("ESA test DEBUG"). UI admin role is separate from API Authorization header.'
            ),
        })
    return _finish(False)


def _esa_distribution_display_name() -> str:
    return 'Cisco ESA'


def _record_esa_distribution_success(contexts: list[dict[str, Any]]) -> None:
    if not contexts:
        return
    try:
        from utils.downstream import record_api_distribution_events

        record_api_distribution_events(
            contexts,
            vendor_id='cisco',
            display_name=_esa_distribution_display_name(),
            api_source='cisco_esa',
        )
    except Exception:
        logger.debug('ESA downstream distribution record failed', exc_info=True)


def _mark_esa_distribution_removed(contexts: list[dict[str, Any]]) -> None:
    if not contexts:
        return
    try:
        from utils.downstream import mark_api_distribution_removed

        mark_api_distribution_removed(
            contexts,
            vendor_id='cisco',
            display_name=_esa_distribution_display_name(),
            api_source='cisco_esa',
        )
    except Exception:
        logger.debug('ESA downstream distribution remove mark failed', exc_info=True)


def sync_add_batch(
    contexts: list[dict[str, Any]],
    *,
    audit_log_fn: Optional[Callable[..., None]] = None,
) -> None:
    """Group IOC creates by ESA dictionary; one POST per dictionary (Basic auth)."""
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
    if ok:
        _record_esa_distribution_success(retry_contexts)
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
    if ok:
        _mark_esa_distribution_removed(retry_contexts)
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
