"""
Trellix Email Security (EX): YARA upload/delete via browser-style session (CookieJar).

Upload (multipart POST): yara_file, f_type, content_type - **default** path
``/ex/yara_rules_ng/upload_yara`` (Email Security web UI).

Delete: POST ``application/x-www-form-urlencoded`` to ``.../yara_rules_ng/delete_yara_files``
(derived from upload path unless ``delete_path`` is set per target).

Session-style push/delete for additional targets reuse ``push_yara_session_targets`` /
``delete_yara_session_targets`` (used by Trellix NX ``api_style: wmps`` in ``utils.trellix_nx``).

Auth flow (per target):
1. GET ``login_path`` (default ``/login/login``) to seed session cookies + optional CSRF from HTML.
2. JSON POST login: ``{"auth_method": "<password|ldap>", "data": {"username", "password"}}``.
   LDAP-backed appliances often still accept ``password``; use ``ldap`` or ``auto`` when needed.
3. Multipart upload with cookies from the same CookieJar (+ X-CSRF-* when available).

Optional manual Cookie; optional per-target csrf_*; ``ex_delete_name_mode: yar_txt`` maps
``rule.yar`` -> ``rule.yar.txt`` for delete payloads when EX stores that suffix.

API/telemetry rows may include ``summary`` (short general outcome), ``message`` (technical detail),
and ``hint`` (likely cause for operators) on failures.
"""

from __future__ import annotations

import http.cookiejar
import json
import logging
import random
import re
import ssl
import string
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlencode
from typing import Any, Callable, List, Optional

from utils.yara_http_push import _evaluate_http_response_body, _truncate_msg

_MAX_RESPONSE_BODY_BYTES = 256 * 1024

# Defaults aligned with current Trellix EX UI (paths / form values may differ on older appliances).
_DEFAULT_EX_LOGIN_PATH = '/login/login'
_DEFAULT_EX_CONTENT_TYPE = 'base'
# EX (Email Security) web UI - NX IPS uses /wmps/... (see utils.trellix_nx, api_style wmps).
_DEFAULT_EX_UPLOAD_PATH = '/ex/yara_rules_ng/upload_yara'
_EX_ACCEPT = 'application/json, text/plain, */*'
_EX_USER_AGENT = 'Mozilla/5.0 (compatible; ZIoCHub/2.0; Trellix-EX-YARA)'
_VALID_AUTH_METHODS = frozenset(('password', 'ldap', 'auto'))
_EX_CONNECTION_TEST_FILENAME = 'ziochub_connection_test.yar'
_EX_CONNECTION_TEST_YARA = """rule ziochub_connection_test {
    meta:
        description = "ZIoCHub connectivity test (safe; condition is false)"
    condition:
        false
}
"""


@dataclass
class _ExAuthResult:
    ok: bool
    message: str
    opener: Optional[urllib.request.OpenerDirector] = None
    jar: Optional[http.cookiejar.CookieJar] = None
    cookie_header: str = ''
    csrf_param: Optional[str] = None
    csrf_token: Optional[str] = None
    verify_ssl: bool = True


def _http_code_from_message(msg: str) -> Optional[int]:
    """Best-effort HTTP status from Trellix error strings (e.g. 'Login HTTP 401', 'HTTP 403; ...')."""
    m = re.search(r"\bHTTP\s+(\d{3})\b", msg or "", re.I)
    if not m:
        m = re.search(r"Login\s+HTTP\s+(\d{3})\b", msg or "", re.I)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _trellix_ex_operator_hint(
    *,
    phase: str,
    message: str = "",
    http_status: Optional[int] = None,
    exc: Optional[BaseException] = None,
) -> str:
    """Short 'likely cause' line for operators (EX / shared wmps session flow). Empty if unknown."""
    msg_l = (message or "").lower()
    code = http_status if isinstance(http_status, int) else _http_code_from_message(message or "")

    if exc is not None:
        exc_s = str(exc).lower()
        if any(x in exc_s for x in ("certificate", "ssl:", "tls", "cert_verify", "hostname")):
            return (
                "Likely: TLS verification failed - use \"Verify TLS: No\" for a quick test, "
                "or install the appliance CA / fix the hostname on the EX target."
            )
        if "timed out" in exc_s or "timeout" in exc_s:
            return "Likely: HTTPS timeout - firewall, slow network path, or the appliance is overloaded."
        if "refused" in exc_s or "errno 111" in exc_s:
            return "Likely: connection refused - wrong port, service down, or firewall blocking this host."
        if "resolve" in exc_s or "getaddrinfo" in exc_s or "name or service not known" in exc_s:
            return "Likely: DNS / hostname - typo in base URL, or this server cannot resolve the EX host."

    if phase == "config":
        if "base" in msg_l and "missing" in msg_l:
            return "Likely: set base_url on the Trellix EX target row (Integrations), save, then test again."

    if phase == "login":
        if code == 401:
            return (
                "Likely: wrong username or password, locked account, or the appliance expects SSO "
                "instead of JSON password login."
            )
        if code == 403:
            return "Likely: WAF, IP allowlist, or policy blocks the login endpoint from this ZIoCHub host."
        if code == 404:
            return "Likely: wrong login_path for this EX build - confirm JSON login URL (often /login/login on Trellix EX)."
        if code == 429:
            return "Likely: rate limiting - wait before retrying automated login."
        if "missing" in msg_l and "username" in msg_l:
            return "Likely: username is empty on the EX target - fill it in and save."
        if "missing" in msg_l and "password" in msg_l:
            return "Likely: password is empty - set it, or paste a manual session Cookie from a browser login if SSO is required."
        if "no session cookies" in msg_l or "no set-cookie" in msg_l:
            return (
                "Likely: LDAP/SSO login JSON succeeded but EX did not issue session cookies to ZIoCHub — "
                "set auth_method to ldap or auto, use DOMAIN\\user or UPN if required, or paste Manual Cookie + CSRF from the browser."
            )
        if "no set-cookie" in msg_l or ("cookie" in msg_l and "upload" in msg_l):
            return "Likely: login returned no session cookie - paste Cookie + CSRF from a browser session on this appliance."

    if phase in ("upload", "delete"):
        if code == 401:
            return "Likely: session cookie expired or invalid - refresh manual Cookie or log in again on the appliance."
        if code == 403:
            return (
                "Likely: CSRF rejected, missing YARA-admin permission, or a reverse proxy/WAF altered the POST."
            )
        if code == 404:
            return (
                "Likely: wrong upload/delete path - Email EX normally uses /ex/yara_rules_ng/...; "
                "/wmps/... is usually IPS web (NX), not EX."
            )
        if code == 419:
            return "Likely: CSRF/session mismatch (token expired). Refresh CSRF/cookie from a browser session on this EX."
        if code == 422:
            return "Likely: appliance validation rejected the payload (f_type, content_type, or rule text for this EX version)."
        if code == 429:
            return "Likely: throttling on the appliance - reduce how often you run the test or automation."
        if code is not None and code >= 500:
            if "application status" in msg_l or "trellix application status" in msg_l:
                return (
                    "Likely: Trellix returned an application status page (HTTP 500) - wrong API path for this host "
                    "(CMS needs /cms/yara_rules_ng/..., EX needs /ex/...), missing CMS sensor fields, or the YARA service is down."
                )
            return "Likely: server-side fault on Trellix EX - check appliance health and application logs."
        if code == 203:
            if "login" in msg_l or "not authenticated" in msg_l:
                return (
                    "Likely: session not accepted — use Manual Cookie (+ CSRF) from a browser on this EX, "
                    "or verify username/password and that base_url matches the host you log into."
                )
            return (
                "Likely: HTTP 203 is unusual for this API - a proxy may be rewriting the response; "
                "hit the EX host directly if possible and compare with the technical line above."
            )
        if "success=false" in msg_l or '"success": false' in msg_l or "'success': false" in msg_l:
            return "Likely: JSON reports failure (error/errors fields) - read the technical message for the appliance reason."
        if "error page" in msg_l or ("<html" in msg_l and "body suggests" in msg_l):
            return "Likely: HTML or login page instead of JSON - wrong URL, expired session, or SSO intercepting the API."

    if phase == "login" and "rejected" in msg_l:
        return "Likely: login JSON indicates failure - verify credentials, login_path, and that JSON login is enabled."

    return ""


def _trellix_ex_failure_row(
    name: str,
    url: str,
    *,
    phase: str,
    summary: str,
    message: str,
    http_status: Optional[int] = None,
    exc: Optional[BaseException] = None,
) -> dict[str, Any]:
    """One result row for a failed EX/wmps step: general summary + technical message + optional hint."""
    code = http_status if isinstance(http_status, int) else _http_code_from_message(message)
    hint = _trellix_ex_operator_hint(phase=phase, message=message, http_status=code, exc=exc)
    row: dict[str, Any] = {
        "name": name,
        "url": url or "",
        "success": False,
        "summary": summary,
        "message": message,
        "phase": phase,
    }
    if hint:
        row["hint"] = hint
    if isinstance(http_status, int):
        row["http_status"] = http_status
    elif isinstance(code, int):
        row["http_status"] = code
    return row


def _extract_csrf_from_login_body(body_bytes: bytes) -> tuple[Optional[str], Optional[str]]:
    """
    Parse login JSON for (csrf_param, csrf_token) used as X-CSRF-Param / X-CSRF-Token on upload.
    Returns (None, None) if not found.
    """
    if not body_bytes:
        return None, None
    try:
        text = body_bytes.decode('utf-8', errors='replace').strip()
    except Exception:
        return None, None
    if not text:
        return None, None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, None
    if not isinstance(data, dict):
        return None, None

    def _from_dict(d: dict) -> tuple[Optional[str], Optional[str]]:
        if not isinstance(d, dict):
            return None, None
        if isinstance(d.get('authenticity_token'), str) and d['authenticity_token'].strip():
            return 'authenticity_token', d['authenticity_token'].strip()
        if isinstance(d.get('csrf_token'), str) and d['csrf_token'].strip():
            return 'authenticity_token', d['csrf_token'].strip()
        if isinstance(d.get('csrfToken'), str) and d['csrfToken'].strip():
            return 'authenticity_token', d['csrfToken'].strip()
        return None, None

    p, t = _from_dict(data)
    if t:
        return p, t
    inner = data.get('data')
    if isinstance(inner, dict):
        p, t = _from_dict(inner)
        if t:
            return p, t
    meta = data.get('meta')
    if isinstance(meta, dict):
        t = meta.get('csrf_token') or meta.get('authenticity_token')
        p = meta.get('csrf_param') or meta.get('csrf-param')
        if isinstance(t, str) and t.strip():
            pp = p.strip() if isinstance(p, str) and p.strip() else 'authenticity_token'
            return pp, t.strip()
    return None, None


def _extract_csrf_from_html(html: str) -> tuple[Optional[str], Optional[str]]:
    """Parse login page HTML for CSRF meta tags (common before JSON LDAP/password login)."""
    if not html:
        return None, None
    patterns = (
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']',
        r'name=["\']csrf-token["\']\s+content=["\']([^"\']+)',
    )
    for pat in patterns:
        m = re.search(pat, html, re.I)
        if m and m.group(1).strip():
            return 'authenticity_token', m.group(1).strip()
    return None, None


def _resolve_auth_methods(target: dict) -> List[str]:
    """Order of auth_method values to try on JSON login POST."""
    raw = (target.get('auth_method') or '').strip().lower()
    if raw == 'ldap':
        return ['ldap']
    if raw == 'auto':
        return ['password', 'ldap']
    return ['password']


def _build_ex_opener(verify_ssl: bool) -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=_ssl_context(verify_ssl)),
    )
    return opener, jar


def _jar_cookie_header_for_url(jar: http.cookiejar.CookieJar, url: str) -> str:
    """Serialize cookies in jar applicable to url as a Cookie request header."""
    req = urllib.request.Request(url)
    jar.add_cookie_header(req)
    return (req.get_header('Cookie') or '').strip()


def _apply_ex_browser_headers(
    req: urllib.request.Request,
    *,
    base_url: str = '',
    referer: str = '',
) -> None:
    req.add_header('User-Agent', _EX_USER_AGENT)
    if referer:
        req.add_header('Referer', referer)
    if base_url:
        req.add_header('Origin', base_url.rstrip('/'))


def _ex_open(auth: _ExAuthResult, req: urllib.request.Request, *, timeout: int):
    """Open request using session opener (CookieJar) or manual cookie + TLS context."""
    if auth.opener is not None:
        return auth.opener.open(req, timeout=timeout)
    ctx = _ssl_context(auth.verify_ssl)
    if auth.cookie_header:
        req.add_header('Cookie', auth.cookie_header)
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def _ex_authenticate_for_target(
    target: dict,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> _ExAuthResult:
    """
    Establish EX web session: manual cookie, or GET warm-up + JSON login with shared CookieJar.
    Fails when login JSON is OK but no session cookies were stored (common LDAP mis-match).
    """
    vs = verify_ssl if verify_ssl is not None else bool(target.get('verify_ssl', True))
    manual = _normalize_manual_cookie(cookie_header or target.get('manual_cookie') or '')
    if manual:
        cp, ct = _csrf_from_target_only(target)
        return _ExAuthResult(
            ok=True,
            message='Using manual Cookie (login skipped)',
            cookie_header=manual,
            csrf_param=cp,
            csrf_token=ct,
            verify_ssl=vs,
        )

    base = (target.get('base_url') or '').strip().rstrip('/')
    if not base:
        return _ExAuthResult(ok=False, message='Missing Trellix EX base URL', verify_ssl=vs)
    login_path = (target.get('login_path') or _DEFAULT_EX_LOGIN_PATH).strip()
    login_url = _join_url(base, login_path)
    upload_url = trellix_ex_upload_url_for_target(target) or base
    user = (target.get('username') or '').strip()
    password = str(target.get('password') or '')
    if not user:
        return _ExAuthResult(ok=False, message='Missing Trellix EX username', verify_ssl=vs)
    if not (password or '').strip():
        return _ExAuthResult(ok=False, message='Missing Trellix EX password (or set a manual Cookie)', verify_ssl=vs)

    opener, jar = _build_ex_opener(vs)
    csrf_p: Optional[str] = None
    csrf_t: Optional[str] = None

    # Seed session cookies (and CSRF) like the browser before JSON login.
    try:
        warm_req = urllib.request.Request(login_url, method='GET')
        _apply_ex_browser_headers(warm_req, base_url=base, referer=login_url)
        warm_req.add_header('Accept', 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8')
        with opener.open(warm_req, timeout=30) as warm_resp:
            warm_bytes = warm_resp.read(_MAX_RESPONSE_BODY_BYTES)
        html = warm_bytes.decode('utf-8', errors='replace')
        csrf_p, csrf_t = _extract_csrf_from_html(html)
    except Exception as e:
        logging.warning('Trellix EX login warm-up GET %s failed (continuing): %s', login_url, e)

    tp0, tt0 = _csrf_from_target_only(target)
    if tt0:
        csrf_t = tt0
    if tp0:
        csrf_p = tp0

    last_err = ''
    for auth_method in _resolve_auth_methods(target):
        body_obj = {'auth_method': auth_method, 'data': {'username': user, 'password': password}}
        body = json.dumps(body_obj, ensure_ascii=False).encode('utf-8')
        req = urllib.request.Request(login_url, data=body, method='POST')
        req.add_header('Content-Type', 'application/json; charset=utf-8')
        req.add_header('Accept', 'application/json, */*;q=0.8')
        req.add_header('X-Requested-With', 'XMLHttpRequest')
        _apply_ex_browser_headers(req, base_url=base, referer=login_url)
        if csrf_t:
            req.add_header('X-CSRF-Token', csrf_t)
            req.add_header('X-CSRF-Param', csrf_p or 'authenticity_token')
        try:
            with opener.open(req, timeout=30) as resp:
                code = resp.getcode()
                body_bytes = resp.read(_MAX_RESPONSE_BODY_BYTES)
            if not (200 <= code < 300):
                last_err = f'Login HTTP {code} (auth_method={auth_method})'
                continue
            logical_ok, detail = _evaluate_http_response_body(code, body_bytes)
            if not logical_ok:
                last_err = detail or f'Login HTTP {code} rejected (auth_method={auth_method})'
                continue
            lp, lt = _merge_csrf_after_login(target, body_bytes)
            if lt:
                csrf_t = lt
            if lp:
                csrf_p = lp
            cookie_hdr = _jar_cookie_header_for_url(jar, upload_url)
            if not cookie_hdr:
                return _ExAuthResult(
                    ok=False,
                    message=(
                        f'Login accepted (auth_method={auth_method}) but no session cookies received. '
                        'LDAP/SSO appliances often require Manual Cookie from a browser session, '
                        'or auth_method ldap/auto on this target.'
                    ),
                    verify_ssl=vs,
                )
            return _ExAuthResult(
                ok=True,
                message=detail or f'Login OK (auth_method={auth_method})',
                opener=opener,
                jar=jar,
                cookie_header=cookie_hdr,
                csrf_param=csrf_p,
                csrf_token=csrf_t,
                verify_ssl=vs,
            )
        except urllib.error.HTTPError as e:
            err_body = ''
            try:
                eb = e.read()
                if eb:
                    err_body = eb.decode('utf-8', errors='replace')[:2000]
            except Exception:
                pass
            last_err = _truncate_msg(f'Login HTTP {e.code} (auth_method={auth_method}); {err_body}')
        except urllib.error.URLError as e:
            last_err = str(e.reason or e)
        except Exception as e:
            logging.exception('Trellix EX login auth_method=%s', auth_method)
            last_err = str(e)

    return _ExAuthResult(ok=False, message=last_err or 'Login failed', verify_ssl=vs)


def parse_trellix_ex_targets_json(raw: str | None) -> List[dict]:
    """Parse stored JSON list of EX targets; invalid input -> []."""
    if not raw or not str(raw).strip():
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [x for x in data if isinstance(x, dict)]


def _legacy_flat_ex_target(get_setting: Callable[[str, str], str]) -> dict:
    """Single-target config from legacy flat system_settings keys."""
    return {
        'name': 'Trellix EX',
        'base_url': (get_setting('trellix_ex_base_url', '') or '').strip().rstrip('/'),
        'login_path': (get_setting('trellix_ex_login_path', _DEFAULT_EX_LOGIN_PATH) or _DEFAULT_EX_LOGIN_PATH).strip(),
        'upload_path': (get_setting('trellix_ex_upload_path', _DEFAULT_EX_UPLOAD_PATH) or '').strip(),
        'username': (get_setting('trellix_ex_username', '') or '').strip(),
        'password': get_setting('trellix_ex_password', '') or '',
        'manual_cookie': (get_setting('trellix_ex_manual_cookie', '') or '').strip(),
        'verify_ssl': _verify_ssl_from_settings(get_setting),
        'f_type': (get_setting('trellix_ex_f_type', 'common') or 'common').strip(),
        'content_type': (get_setting('trellix_ex_content_type', _DEFAULT_EX_CONTENT_TYPE) or _DEFAULT_EX_CONTENT_TYPE).strip(),
        'csrf_param': (get_setting('trellix_ex_csrf_param', '') or '').strip(),
        'csrf_token': (get_setting('trellix_ex_csrf_token', '') or '').strip(),
    }


def _coerce_verify_ssl(val: Any, fallback: bool) -> bool:
    if val is None:
        return fallback
    if isinstance(val, str):
        return val.strip().lower() in ('true', '1', 'yes')
    return bool(val)


def normalize_ex_target_row(r: dict, get_setting: Callable[[str, str], str]) -> dict:
    """One resolved target dict for login/upload (defaults from legacy keys when a field is empty)."""
    name = (r.get('name') or '').strip() or 'Trellix EX'
    base_url = (r.get('base_url') or '').strip().rstrip('/')
    login_path = (r.get('login_path') or '').strip() or (
        get_setting('trellix_ex_login_path', _DEFAULT_EX_LOGIN_PATH) or _DEFAULT_EX_LOGIN_PATH
    ).strip()
    upload_path = (r.get('upload_path') or '').strip() or (
        get_setting('trellix_ex_upload_path', _DEFAULT_EX_UPLOAD_PATH) or ''
    ).strip()
    if upload_path and not upload_path.startswith('/'):
        upload_path = '/' + upload_path
    username = (r.get('username') or '').strip()
    password = str(r.get('password') or '')
    manual_raw = r.get('manual_cookie')
    manual_cookie = (manual_raw if isinstance(manual_raw, str) else str(manual_raw or '')).strip()
    verify_ssl = _coerce_verify_ssl(r.get('verify_ssl'), _verify_ssl_from_settings(get_setting))
    f_type = (r.get('f_type') or '').strip() or (get_setting('trellix_ex_f_type', 'common') or 'common').strip() or 'common'
    ct = (r.get('content_type') or '').strip() or (
        get_setting('trellix_ex_content_type', _DEFAULT_EX_CONTENT_TYPE) or _DEFAULT_EX_CONTENT_TYPE
    ).strip() or _DEFAULT_EX_CONTENT_TYPE
    csrf_param = (r.get('csrf_param') or '').strip()
    csrf_token = (r.get('csrf_token') or '').strip()
    delete_path = (r.get('delete_path') or '').strip()
    ex_delete_name_mode = (r.get('ex_delete_name_mode') or 'same').strip().lower()
    if ex_delete_name_mode not in ('same', 'yar_txt'):
        ex_delete_name_mode = 'same'
    auth_method = (r.get('auth_method') or 'password').strip().lower()
    if auth_method not in _VALID_AUTH_METHODS:
        auth_method = 'password'
    return {
        'name': name,
        'base_url': base_url,
        'login_path': login_path,
        'upload_path': upload_path,
        'username': username,
        'password': password,
        'manual_cookie': manual_cookie,
        'verify_ssl': verify_ssl,
        'f_type': f_type,
        'content_type': ct,
        'csrf_param': csrf_param,
        'csrf_token': csrf_token,
        'delete_path': delete_path,
        'ex_delete_name_mode': ex_delete_name_mode,
        'auth_method': auth_method,
    }


def list_trellix_ex_targets(get_setting: Callable[[str, str], str]) -> List[dict]:
    """
    Targets with base_url set. If ``trellix_ex_targets`` JSON is empty, falls back to legacy flat keys
    (same behaviour as before multi-target).
    """
    rows = parse_trellix_ex_targets_json(get_setting('trellix_ex_targets', '[]'))
    rows = [normalize_ex_target_row(r, get_setting) for r in rows if (r.get('base_url') or '').strip()]
    if not rows:
        leg = _legacy_flat_ex_target(get_setting)
        if leg['base_url']:
            rows = [normalize_ex_target_row(leg, get_setting)]
    return rows


def trellix_ex_upload_url_for_target(target: dict) -> str:
    base = (target.get('base_url') or '').strip().rstrip('/')
    up = (target.get('upload_path') or '').strip()
    if not up.startswith('/'):
        up = '/' + up if up else ''
    return _join_url(base, up) if base else ''


def trellix_ex_referer_path(upload_path: str) -> str:
    """Settings page path for Referer header (must match UI prefix: wmps, ex, ...)."""
    up = (upload_path or '').strip()
    if '/yara_rules_ng/' in up:
        prefix = up.split('/yara_rules_ng/')[0].strip() or '/ex'
        if not prefix.startswith('/'):
            prefix = '/' + prefix
        return prefix + '/settings/yara_rules'
    if up.startswith('/wmps'):
        return '/wmps/settings/yara_rules'
    return '/ex/settings/yara_rules'


def trellix_ex_delete_path_from_upload(upload_path: str) -> str:
    """Derive delete_yara_files path from upload_yara path."""
    up = (upload_path or '').strip()
    if 'upload_yara' in up:
        return up.replace('upload_yara', 'delete_yara_files', 1)
    if '/yara_rules_ng/' in up:
        return up.rstrip('/').rsplit('/', 1)[0] + '/delete_yara_files'
    return '/ex/yara_rules_ng/delete_yara_files'


def trellix_ex_delete_url_for_target(target: dict) -> str:
    base = (target.get('base_url') or '').strip().rstrip('/')
    if not base:
        return ''
    explicit = (target.get('delete_path') or '').strip()
    if explicit:
        if not explicit.startswith('/'):
            explicit = '/' + explicit
        return _join_url(base, explicit)
    up = (target.get('upload_path') or '').strip()
    del_rel = trellix_ex_delete_path_from_upload(up)
    return _join_url(base, del_rel)


def list_trellix_ex_upload_urls(get_setting: Callable[[str, str], str]) -> List[str]:
    out: List[str] = []
    for t in list_trellix_ex_targets(get_setting):
        u = trellix_ex_upload_url_for_target(t)
        if u:
            out.append(u)
    return out


def list_trellix_ex_delete_urls(get_setting: Callable[[str, str], str]) -> List[str]:
    """Delete API URLs for retry / telemetry matching."""
    out: List[str] = []
    for t in list_trellix_ex_targets(get_setting):
        u = trellix_ex_delete_url_for_target(t)
        if u:
            out.append(u)
    return out


def _ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if verify_ssl:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _join_url(base: str, path: str) -> str:
    b = (base or "").strip().rstrip("/")
    p = (path or "").strip()
    if not p:
        return b
    if not p.startswith("/"):
        p = "/" + p
    return b + p if b else p


def trellix_ex_upload_url(get_setting: Callable[[str, str], str]) -> str:
    """Primary upload URL for telemetry / retry matching (first target, or legacy flat keys)."""
    tgts = list_trellix_ex_targets(get_setting)
    if tgts:
        return trellix_ex_upload_url_for_target(tgts[0])
    base = (get_setting("trellix_ex_base_url", "") or "").strip().rstrip("/")
    up = (get_setting("trellix_ex_upload_path", _DEFAULT_EX_UPLOAD_PATH) or "").strip()
    if not up.startswith("/"):
        up = "/" + up
    return _join_url(base, up) if base else ""


def trellix_ex_enabled(get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting("trellix_ex_enabled", "false") or "false").lower() in ("true", "1", "yes")


def _verify_ssl_from_settings(get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting("trellix_ex_verify_ssl", "true") or "true").lower() in ("true", "1", "yes")


def _normalize_manual_cookie(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    low = s.lower()
    if low.startswith("cookie:"):
        s = s.split(":", 1)[1].strip()
    return s


def _csrf_from_target_only(target: dict) -> tuple[Optional[str], Optional[str]]:
    """Optional static CSRF from target row (e.g. with manual Cookie)."""
    tp = (target.get("csrf_param") or "").strip() or None
    tt = (target.get("csrf_token") or "").strip() or None
    if tt and not tp:
        tp = "authenticity_token"
    return tp, tt


def _merge_csrf_after_login(target: dict, body_bytes: bytes) -> tuple[Optional[str], Optional[str]]:
    """Prefer token/param from target JSON if set; else parse login body; default param for Rails."""
    ep, et = _extract_csrf_from_login_body(body_bytes)
    tp = (target.get("csrf_param") or "").strip()
    tt = (target.get("csrf_token") or "").strip()
    if tt:
        et = tt
    if tp:
        ep = tp
    if et and not ep:
        ep = "authenticity_token"
    return ep, et


def trellix_ex_login_for_target(
    target: dict,
    *,
    verify_ssl: Optional[bool] = None,
) -> tuple[bool, str, str, tuple[Optional[str], Optional[str]]]:
    """
    Establish session for one EX target (GET warm-up + JSON login, or manual cookie).

    Returns (ok, cookie_header_or_empty, message, (csrf_param, csrf_token)).
    """
    auth = _ex_authenticate_for_target(target, verify_ssl=verify_ssl)
    return (
        auth.ok,
        auth.cookie_header,
        auth.message,
        (auth.csrf_param, auth.csrf_token),
    )


def trellix_ex_login(
    get_setting: Callable[[str, str], str],
    *,
    verify_ssl: Optional[bool] = None,
) -> tuple[bool, str, str, tuple[Optional[str], Optional[str]]]:
    """Login for the first configured target."""
    tgts = list_trellix_ex_targets(get_setting)
    if not tgts:
        return False, "", "No Trellix EX targets configured", (None, None)
    t0 = tgts[0]
    vs = verify_ssl if verify_ssl is not None else bool(t0.get("verify_ssl", True))
    return trellix_ex_login_for_target(t0, verify_ssl=vs)


def _session_product_name(target: dict) -> str:
    """Human label for session-style push/delete (EX, NX wmps, CMS)."""
    return ((target.get("product_name") or target.get("name") or "Trellix EX").strip() or "Trellix EX")


def _maybe_wmps_session_warmup(auth: _ExAuthResult, target: dict) -> None:
    """Prime NX wmps YARA UI session (GET file types / list / errors) before upload/delete."""
    up = (target.get("upload_path") or "").strip()
    if "/wmps/" not in up:
        return
    if not target.get("wmps_warmup", True):
        return
    try:
        from utils.trellix_nx import wmps_yara_ui_warmup

        wmps_yara_ui_warmup(auth, target)
    except Exception:
        logging.debug("wmps session warmup skipped or failed", exc_info=True)


def _target_form_extra_pairs(target: dict) -> list[tuple[str, str]]:
    """Optional extra multipart/urlencoded fields from target (e.g. Trellix CMS sensor scope)."""
    out: list[tuple[str, str]] = []
    raw = target.get('form_extra')
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                name = str(item.get('name') or '').strip()
                if not name:
                    continue
                val = item.get('value')
                out.append((name, '' if val is None else str(val)))
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                name = str(item[0]).strip()
                if name:
                    out.append((name, str(item[1])))
    return out


def _multipart_body(
    filename: str,
    content: str,
    f_type: str,
    content_type_val: str,
    *,
    extra_fields: Optional[list[tuple[str, str]]] = None,
) -> tuple[str, bytes]:
    boundary = "----ziochubTrellixEx" + "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(24)
    )
    file_bytes = content.encode("utf-8")
    crlf = b"\r\n"
    parts: list[bytes] = []

    def add_field(name: str, value: str) -> None:
        disp = f'Content-Disposition: form-data; name="{name}"'
        parts.append(f"--{boundary}".encode("ascii") + crlf)
        parts.append(disp.encode("utf-8") + crlf + crlf)
        parts.append(value.encode("utf-8") + crlf)

    fn = (filename or "rule.yar").replace("\r", "").replace("\n", "").replace('"', "").strip() or "rule.yar"
    for ename, evalue in extra_fields or []:
        add_field(ename, evalue)
    add_field("f_type", f_type)
    add_field("content_type", content_type_val)

    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="yara_file"; filename="{fn}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    )
    parts.append(head.encode("utf-8"))
    parts.append(file_bytes + crlf)
    parts.append(f"--{boundary}--\r\n".encode("ascii"))
    body = b"".join(parts)
    return boundary, body


def _push_yara_trellix_ex_one(
    content: str,
    filename: str,
    target: dict,
    audit_log_fn,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict[str, Any]:
    """Login + multipart upload for a single resolved EX target."""
    name = ((target.get("name") or "Trellix EX").strip() or "Trellix EX")
    upload_url = trellix_ex_upload_url_for_target(target)
    if not upload_url:
        audit_log_fn("yara_push_skip", f"target=Trellix_EX name={name} reason=missing_base_url")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    "",
                    phase="config",
                    summary="Trellix EX target is incomplete.",
                    message="Missing Trellix EX base URL",
                )
            ],
        }

    vs = verify_ssl if verify_ssl is not None else bool(target.get("verify_ssl", True))
    if not vs:
        logging.warning("Trellix EX YARA push (%s): TLS certificate verification is disabled", name)

    f_type = (target.get("f_type") or "common").strip() or "common"
    ct_val = (target.get("content_type") or _DEFAULT_EX_CONTENT_TYPE).strip() or _DEFAULT_EX_CONTENT_TYPE

    product = _session_product_name(target)
    auth = _ex_authenticate_for_target(target, verify_ssl=vs, cookie_header=cookie_header)
    if not auth.ok:
        audit_log_fn("yara_push_fail", f"file={filename} target={product} name={name} login={auth.message[:300]}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    upload_url,
                    phase="login",
                    summary=f"{product} login failed.",
                    message=auth.message,
                )
            ],
        }

    _maybe_wmps_session_warmup(auth, target)
    csrf_p, csrf_t = auth.csrf_param, auth.csrf_token
    boundary, body = _multipart_body(
        filename, content, f_type, ct_val, extra_fields=_target_form_extra_pairs(target)
    )
    req = urllib.request.Request(upload_url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Accept", _EX_ACCEPT)
    req.add_header("X-Requested-With", "XMLHttpRequest")
    if csrf_t:
        req.add_header("X-CSRF-Token", csrf_t)
        req.add_header("X-CSRF-Param", csrf_p or "authenticity_token")
    base_ref = (target.get("base_url") or "").strip().rstrip("/")
    up_path = (target.get("upload_path") or "").strip()
    referer = _join_url(base_ref, trellix_ex_referer_path(up_path)) if base_ref else ''
    _apply_ex_browser_headers(req, base_url=base_ref, referer=referer)
    if auth.opener is None and auth.cookie_header:
        req.add_header("Cookie", auth.cookie_header)

    try:
        with _ex_open(auth, req, timeout=60) as resp:
            code = resp.getcode()
            body_bytes = b""
            try:
                body_bytes = resp.read(_MAX_RESPONSE_BODY_BYTES)
            except Exception:
                pass
            if 200 <= code < 300:
                logical_ok, detail_msg = _evaluate_http_response_body(code, body_bytes)
                if logical_ok:
                    audit_log_fn("yara_push_ok", f"file={filename} target=EX name={name} code={code}")
                else:
                    audit_log_fn(
                        "yara_push_fail",
                        f"file={filename} target=EX name={name} code={code} detail={detail_msg[:500]}",
                    )
                if logical_ok:
                    return {
                        "overall_success": True,
                        "results": [
                            {
                                "name": name,
                                "url": upload_url,
                                "success": True,
                                "message": detail_msg,
                                "http_status": code,
                                "phase": "upload",
                            }
                        ],
                    }
                return {
                    "overall_success": False,
                    "results": [
                        _trellix_ex_failure_row(
                            name,
                            upload_url,
                            phase="upload",
                            summary="Trellix EX reported the YARA upload did not succeed.",
                            message=detail_msg,
                            http_status=code,
                        )
                    ],
                }
            audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} code={code}")
            return {
                "overall_success": False,
                "results": [
                    _trellix_ex_failure_row(
                        name,
                        upload_url,
                        phase="upload",
                        summary="Trellix EX returned a non-success HTTP status during upload.",
                        message=f"HTTP {code}",
                        http_status=code,
                    )
                ],
            }
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            eb = e.read()
            if eb:
                err_body = eb.decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        msg = _truncate_msg(f"HTTP {e.code} {e.reason}; {err_body}")
        audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} code={e.code}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    upload_url,
                    phase="upload",
                    summary="Trellix EX returned an HTTP error during YARA upload.",
                    message=msg,
                    http_status=e.code,
                    exc=e,
                )
            ],
        }
    except urllib.error.URLError as e:
        audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} error={e.reason}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    upload_url,
                    phase="upload",
                    summary="Could not reach Trellix EX over HTTPS (YARA upload).",
                    message=str(e.reason or e),
                    exc=e,
                )
            ],
        }
    except Exception as e:
        logging.exception("Trellix EX YARA push")
        audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} error={e}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    upload_url,
                    phase="upload",
                    summary="Unexpected error while pushing YARA to Trellix EX.",
                    message=str(e),
                    exc=e,
                )
            ],
        }


def _ex_delete_remote_filename(filename: str, target: dict) -> str:
    """
    EX delete API expects files[0][name] as stored on appliance.
    Mode yar_txt: rule.yar -> rule.yar.txt (matches common EX UI naming).
    """
    mode = (target.get("ex_delete_name_mode") or "same").strip().lower()
    fn = (filename or "").strip()
    if mode == "yar_txt" and fn.lower().endswith(".yar"):
        return fn + ".txt"
    return fn


def _delete_yara_trellix_ex_one_with_fallbacks(
    filename: str,
    target: dict,
    audit_log_fn,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict[str, Any]:
    """
    Delete on EX; if the configured ex_delete_name_mode does not match how the rule
    was stored, retry with the alternate mode (yar <-> yar.txt).
    """
    primary = _delete_yara_trellix_ex_one(
        filename, target, audit_log_fn, verify_ssl=verify_ssl, cookie_header=cookie_header
    )
    if primary.get("overall_success"):
        return primary
    fn = (filename or "").strip()
    if not fn.lower().endswith(".yar"):
        return primary
    mode = (target.get("ex_delete_name_mode") or "same").strip().lower()
    alt_mode = "same" if mode == "yar_txt" else "yar_txt"
    alt_target = {**target, "ex_delete_name_mode": alt_mode}
    alt = _delete_yara_trellix_ex_one(
        filename, alt_target, audit_log_fn, verify_ssl=verify_ssl, cookie_header=cookie_header
    )
    if alt.get("overall_success"):
        return alt
    return primary


def _delete_yara_trellix_ex_one(
    filename: str,
    target: dict,
    audit_log_fn,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict[str, Any]:
    """POST application/x-www-form-urlencoded to delete_yara_files (Trellix EX web UI API)."""
    name = ((target.get("name") or "Trellix EX").strip() or "Trellix EX")
    delete_url = trellix_ex_delete_url_for_target(target)
    if not delete_url:
        audit_log_fn("yara_delete_skip", f"target=EX name={name} reason=missing_base_url")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    "",
                    phase="config",
                    summary="Trellix EX target is incomplete.",
                    message="Missing Trellix EX base URL",
                )
            ],
        }

    vs = verify_ssl if verify_ssl is not None else bool(target.get("verify_ssl", True))
    if not vs:
        logging.warning("Trellix EX YARA delete (%s): TLS certificate verification is disabled", name)

    f_type = (target.get("f_type") or "common").strip() or "common"
    ct_val = (target.get("content_type") or _DEFAULT_EX_CONTENT_TYPE).strip() or _DEFAULT_EX_CONTENT_TYPE
    remote_name = _ex_delete_remote_filename(filename, target)

    product = _session_product_name(target)
    auth = _ex_authenticate_for_target(target, verify_ssl=vs, cookie_header=cookie_header)
    if not auth.ok:
        audit_log_fn("yara_delete_fail", f"file={filename} target={product} name={name} login={auth.message[:300]}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    delete_url,
                    phase="login",
                    summary=f"{product} login failed (delete not attempted).",
                    message=auth.message,
                )
            ],
        }

    _maybe_wmps_session_warmup(auth, target)
    csrf_p, csrf_t = auth.csrf_param, auth.csrf_token
    delete_pairs: list[tuple[str, str]] = list(_target_form_extra_pairs(target))
    delete_pairs.extend(
        [
            ("files[0][name]", remote_name),
            ("files[0][c_type]", ct_val),
            ("files[0][type]", f_type),
        ]
    )
    body = urlencode(delete_pairs).encode("utf-8")
    req = urllib.request.Request(delete_url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
    req.add_header("Accept", _EX_ACCEPT)
    req.add_header("X-Requested-With", "XMLHttpRequest")
    if csrf_t:
        req.add_header("X-CSRF-Token", csrf_t)
        req.add_header("X-CSRF-Param", csrf_p or "authenticity_token")
    base_ref = (target.get("base_url") or "").strip().rstrip("/")
    up_path = (target.get("upload_path") or "").strip()
    referer = _join_url(base_ref, trellix_ex_referer_path(up_path)) if base_ref else ''
    _apply_ex_browser_headers(req, base_url=base_ref, referer=referer)
    if auth.opener is None and auth.cookie_header:
        req.add_header("Cookie", auth.cookie_header)

    try:
        with _ex_open(auth, req, timeout=60) as resp:
            code = resp.getcode()
            body_bytes = b""
            try:
                body_bytes = resp.read(_MAX_RESPONSE_BODY_BYTES)
            except Exception:
                pass
            if 200 <= code < 300:
                logical_ok, detail_msg = _evaluate_http_response_body(code, body_bytes)
                if logical_ok:
                    audit_log_fn(
                        "yara_delete_ok",
                        f"file={filename} remote={remote_name!r} target=EX name={name} code={code}",
                    )
                else:
                    audit_log_fn(
                        "yara_delete_fail",
                        f"file={filename} target=EX name={name} code={code} detail={detail_msg[:500]}",
                    )
                if logical_ok:
                    return {
                        "overall_success": True,
                        "results": [
                            {
                                "name": name,
                                "url": delete_url,
                                "success": True,
                                "message": detail_msg,
                                "http_status": code,
                                "phase": "delete",
                            }
                        ],
                    }
                return {
                    "overall_success": False,
                    "results": [
                        _trellix_ex_failure_row(
                            name,
                            delete_url,
                            phase="delete",
                            summary="Trellix EX reported the YARA delete did not succeed.",
                            message=detail_msg,
                            http_status=code,
                        )
                    ],
                }
            audit_log_fn("yara_delete_fail", f"file={filename} target=EX name={name} code={code}")
            return {
                "overall_success": False,
                "results": [
                    _trellix_ex_failure_row(
                        name,
                        delete_url,
                        phase="delete",
                        summary="Trellix EX returned a non-success HTTP status during delete.",
                        message=f"HTTP {code}",
                        http_status=code,
                    )
                ],
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            audit_log_fn("yara_delete_ok", f"file={filename} remote={remote_name!r} target=EX name={name} code=404")
            return {
                "overall_success": True,
                "results": [
                    {
                        "name": name,
                        "url": delete_url,
                        "success": True,
                        "summary": "Rule not present on Trellix EX (nothing to delete).",
                        "message": "HTTP 404 (already absent)",
                        "http_status": 404,
                        "phase": "delete",
                    }
                ],
            }
        err_body = ""
        try:
            eb = e.read()
            if eb:
                err_body = eb.decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        msg = _truncate_msg(f"HTTP {e.code} {e.reason}; {err_body}")
        audit_log_fn("yara_delete_fail", f"file={filename} target=EX name={name} code={e.code}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    delete_url,
                    phase="delete",
                    summary="Trellix EX returned an HTTP error during YARA delete.",
                    message=msg,
                    http_status=e.code,
                    exc=e,
                )
            ],
        }
    except urllib.error.URLError as e:
        audit_log_fn("yara_delete_fail", f"file={filename} target=EX name={name} error={e.reason}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    delete_url,
                    phase="delete",
                    summary="Could not reach Trellix EX over HTTPS (YARA delete).",
                    message=str(e.reason or e),
                    exc=e,
                )
            ],
        }
    except Exception as e:
        logging.exception("Trellix EX YARA delete")
        audit_log_fn("yara_delete_fail", f"file={filename} target=EX name={name} error={e}")
        return {
            "overall_success": False,
            "results": [
                _trellix_ex_failure_row(
                    name,
                    delete_url,
                    phase="delete",
                    summary="Unexpected error while deleting YARA on Trellix EX.",
                    message=str(e),
                    exc=e,
                )
            ],
        }


def delete_yara_session_targets(
    filename: str,
    targets: List[dict],
    audit_log_fn,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
    empty_skip_log: str = "yara_delete_skip",
    empty_log_detail: str = "reason=no_targets",
    empty_result_name: str = "-",
    empty_message: str = "No targets configured",
) -> dict[str, Any]:
    """Run session-cookie YARA delete for each target dict (EX or NX wmps - same HTTP shape)."""
    if not audit_log_fn:
        def _noop(*_a, **_k):
            pass

        audit_log_fn = _noop

    if not targets:
        audit_log_fn(empty_skip_log, empty_log_detail)
        return {
            "overall_success": False,
            "results": [{"name": empty_result_name, "url": "", "success": False, "message": empty_message}],
        }

    results: list[dict[str, Any]] = []
    overall = True
    shared = (cookie_header or "").strip()
    n = len(targets)
    for _i, t in enumerate(targets):
        ck = shared if (shared and n == 1) else None
        one = _delete_yara_trellix_ex_one_with_fallbacks(
            filename, t, audit_log_fn, verify_ssl=verify_ssl, cookie_header=ck
        )
        row = (one.get("results") or [{}])[0]
        results.append(row)
        overall = overall and bool(one.get("overall_success"))

    return {"overall_success": overall, "results": results}


def push_yara_session_targets(
    content: str,
    filename: str,
    targets: List[dict],
    audit_log_fn,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
    empty_skip_log: str = "yara_push_skip",
    empty_log_detail: str = "reason=no_targets",
    empty_result_name: str = "-",
    empty_message: str = "No targets configured",
) -> dict[str, Any]:
    """Run session-cookie YARA multipart upload for each target dict (EX or NX wmps)."""
    if not audit_log_fn:
        def _noop(*_a, **_k):
            pass

        audit_log_fn = _noop

    if not targets:
        audit_log_fn(empty_skip_log, empty_log_detail)
        return {
            "overall_success": False,
            "results": [{"name": empty_result_name, "url": "", "success": False, "message": empty_message}],
        }

    results: list[dict[str, Any]] = []
    overall = True
    shared = (cookie_header or "").strip()
    n = len(targets)
    for _i, t in enumerate(targets):
        ck = shared if (shared and n == 1) else None
        one = _push_yara_trellix_ex_one(content, filename, t, audit_log_fn, verify_ssl=verify_ssl, cookie_header=ck)
        row = (one.get("results") or [{}])[0]
        results.append(row)
        overall = overall and bool(one.get("overall_success"))

    return {"overall_success": overall, "results": results}


def delete_yara_trellix_ex(
    filename: str,
    get_setting: Callable[[str, str], str],
    audit_log_fn=None,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict[str, Any]:
    """Remove YARA from each configured EX target (same result shape as delete_yara_from_appliances)."""
    targets = list_trellix_ex_targets(get_setting)
    return delete_yara_session_targets(
        filename,
        targets,
        audit_log_fn,
        verify_ssl=verify_ssl,
        cookie_header=cookie_header,
        empty_skip_log="yara_delete_skip",
        empty_log_detail="target=EX reason=no_targets",
        empty_result_name="Trellix EX",
        empty_message="No Trellix EX targets configured",
    )


def push_yara_trellix_ex(
    content: str,
    filename: str,
    get_setting: Callable[[str, str], str],
    audit_log_fn=None,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict[str, Any]:
    """
    For each configured EX target: login (unless manual cookie / optional shared cookie for single target),
    then multipart POST. Returns aggregate shape matching ``push_yara_to_appliances``.
    """
    targets = list_trellix_ex_targets(get_setting)
    return push_yara_session_targets(
        content,
        filename,
        targets,
        audit_log_fn,
        verify_ssl=verify_ssl,
        cookie_header=cookie_header,
        empty_skip_log="yara_push_skip",
        empty_log_detail="target=Trellix_EX reason=no_targets",
        empty_result_name="Trellix EX",
        empty_message="No Trellix EX targets configured",
    )


def _test_ex_precheck(get_setting: Callable[[str, str], str]) -> Optional[dict[str, Any]]:
    """Return an error payload when the integration cannot be tested, else None."""
    if not trellix_ex_enabled(get_setting):
        return {
            "success": False,
            "overall_success": False,
            "results": [],
            "headline": "Trellix EX integration is disabled.",
            "summary": "Enable Trellix EX under Integrations, save settings, then run the test again.",
            "message": "Trellix EX is disabled.",
            "hint": "Set Enable Trellix EX YARA push to Yes, save, then retry.",
        }
    if not list_trellix_ex_targets(get_setting):
        return {
            "success": True,
            "overall_success": False,
            "results": [],
            "headline": "No Trellix EX targets configured.",
            "summary": "Add at least one target with a base URL, save, then run the test again.",
            "message": "No targets in trellix_ex_targets.",
        }
    return None


def _auth_row_from_target(target: dict, *, verify_ssl: Optional[bool]) -> dict[str, Any]:
    """One per-target authentication result for the staged admin test."""
    name = ((target.get("name") or "Trellix EX").strip() or "Trellix EX")
    vs = verify_ssl if verify_ssl is not None else bool(target.get("verify_ssl", True))
    auth = _ex_authenticate_for_target(target, verify_ssl=vs)
    ok = auth.ok
    hint = ""
    if not ok:
        hint = _trellix_ex_operator_hint(phase="login", message=auth.message)
    return {
        "name": name,
        "url": _join_url((target.get("base_url") or "").strip().rstrip("/"), (target.get("login_path") or _DEFAULT_EX_LOGIN_PATH).strip()),
        "success": ok,
        "phase": "login",
        "summary": "Authentication succeeded." if ok else "Authentication failed.",
        "message": auth.message,
        "hint": hint or None,
    }


def _aggregate_step_messages(results: list[dict[str, Any]]) -> tuple[str, str, str]:
    """Return (technical_message, combined_hints, combined_summaries) from per-target rows."""
    msgs: list[str] = []
    hints: list[str] = []
    summaries: list[str] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        if (r.get("message") or "").strip():
            msgs.append(str(r.get("message") or "").strip())
        if not r.get("success"):
            hn = (r.get("name") or "Target").strip()
            if (r.get("hint") or "").strip():
                hints.append(f"{hn}: {(r.get('hint') or '').strip()}")
            if (r.get("summary") or "").strip():
                summaries.append(str(r.get("summary") or "").strip())
    msg = "; ".join(msgs)[:900] if msgs else ""
    agg_hint = "\n".join(hints)[:2000] if hints else ""
    agg_summary = ""
    if summaries:
        agg_summary = summaries[0] if len(summaries) == 1 else "; ".join(list(dict.fromkeys(summaries)))[:500]
    return msg, agg_hint, agg_summary


def _step_response(
    *,
    step: str,
    step_number: int,
    overall_success: bool,
    headline: str,
    subline: str,
    results: list[dict[str, Any]],
    message: str = "",
    hint: str = "",
    summary: str = "",
    test_filename: str = "",
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "success": True,
        "step": step,
        "step_number": step_number,
        "overall_success": overall_success,
        "headline": headline,
        "subline": subline,
        "results": results,
        "message": message,
    }
    if hint:
        out["hint"] = hint
    if summary:
        out["summary"] = summary
    if test_filename:
        out["test_filename"] = test_filename
    return out


def test_trellix_ex_step(
    get_setting: Callable[[str, str], str],
    step: str,
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    """
    Run one staged Trellix EX integration test step: auth | upload | cleanup.
    Used by the Admin UI to show progress with a pause between each operation.
    """
    step_l = (step or "").strip().lower()
    pre = _test_ex_precheck(get_setting)
    if pre:
        pre["step"] = step_l
        return pre

    targets = list_trellix_ex_targets(get_setting)
    n = len(targets)

    if step_l == "auth":
        rows = [_auth_row_from_target(t, verify_ssl=verify_ssl) for t in targets]
        ok = bool(rows) and all(r.get("success") for r in rows)
        msg, hint, summ = _aggregate_step_messages(rows)
        if ok:
            headline = "Authentication completed successfully"
            subline = f"Session established for {n} target{'s' if n != 1 else ''}."
        else:
            headline = "Authentication failed"
            subline = "Could not establish a valid session on one or more targets."
        return _step_response(
            step="auth",
            step_number=1,
            overall_success=ok,
            headline=headline,
            subline=subline,
            results=rows,
            message=msg,
            hint=hint,
            summary=summ or headline,
        )

    if step_l == "upload":
        res = push_yara_trellix_ex(
            _EX_CONNECTION_TEST_YARA,
            _EX_CONNECTION_TEST_FILENAME,
            get_setting,
            audit_log_fn=lambda *a, **k: None,
            verify_ssl=verify_ssl,
        )
        rows = list(res.get("results") or [])
        ok = bool(res.get("overall_success"))
        msg, hint, summ = _aggregate_step_messages(rows)
        fn = _EX_CONNECTION_TEST_FILENAME
        if ok:
            headline = "Test rule uploaded successfully"
            subline = f"Uploaded {fn} to {n} target{'s' if n != 1 else ''} (condition: false, no matches)."
        else:
            headline = "Test rule upload failed"
            subline = f"Could not upload {fn} to all configured targets."
        return _step_response(
            step="upload",
            step_number=2,
            overall_success=ok,
            headline=headline,
            subline=subline,
            results=rows,
            message=msg,
            hint=hint,
            summary=summ or headline,
            test_filename=fn,
        )

    if step_l == "cleanup":
        res = delete_yara_trellix_ex(
            _EX_CONNECTION_TEST_FILENAME,
            get_setting,
            audit_log_fn=lambda *a, **k: None,
            verify_ssl=verify_ssl,
        )
        rows = list(res.get("results") or [])
        ok = bool(res.get("overall_success"))
        msg, hint, summ = _aggregate_step_messages(rows)
        fn = _EX_CONNECTION_TEST_FILENAME
        if ok:
            headline = "Test rule cleanup completed successfully"
            subline = f"Removed {fn} from {n} target{'s' if n != 1 else ''}."
        else:
            headline = "Test rule cleanup failed"
            subline = (
                f"{fn} may still be present on the appliance. "
                "Try Delete name mode yar_txt if rules are stored as .yar.txt."
            )
        return _step_response(
            step="cleanup",
            step_number=3,
            overall_success=ok,
            headline=headline,
            subline=subline,
            results=rows,
            message=msg,
            hint=hint,
            summary=summ or headline,
            test_filename=fn,
        )

    return {
        "success": False,
        "overall_success": False,
        "step": step_l,
        "headline": "Unknown test step.",
        "message": f"Invalid step: {step!r}. Use auth, upload, or cleanup.",
    }


def test_trellix_ex_connection(get_setting: Callable[[str, str], str], *, verify_ssl: Optional[bool] = None) -> dict[str, Any]:
    """Admin test (single request): auth, upload, cleanup combined. Prefer staged steps in the UI."""
    pre = _test_ex_precheck(get_setting)
    if pre:
        return pre

    auth = test_trellix_ex_step(get_setting, "auth", verify_ssl=verify_ssl)
    if not auth.get("overall_success"):
        auth["cleanup_success"] = None
        return auth

    upload = test_trellix_ex_step(get_setting, "upload", verify_ssl=verify_ssl)
    cleanup_ok = None
    cleanup_message = ""
    cleanup_hint = ""
    if upload.get("overall_success"):
        cleanup = test_trellix_ex_step(get_setting, "cleanup", verify_ssl=verify_ssl)
        cleanup_ok = bool(cleanup.get("overall_success"))
        cleanup_message = (cleanup.get("subline") or cleanup.get("headline") or "")[:500]
        cleanup_hint = (cleanup.get("hint") or "")[:2000]

    ok = bool(upload.get("overall_success"))
    out: dict[str, Any] = {
        "success": True,
        "overall_success": ok and (cleanup_ok is not False),
        "results": upload.get("results", []),
        "message": upload.get("message", ""),
        "headline": "Trellix EX integration test completed successfully" if ok and cleanup_ok is not False else "Trellix EX integration test completed with errors",
    }
    if upload.get("hint"):
        out["hint"] = upload["hint"]
    if upload.get("summary"):
        out["summary"] = upload["summary"]
    if cleanup_ok is not None:
        out["cleanup_success"] = cleanup_ok
        out["cleanup_message"] = cleanup_message
    if ok and cleanup_ok is False and cleanup_hint:
        out["cleanup_hint"] = cleanup_hint
        out["hint"] = f"{out.get('hint', '')}\n{cleanup_hint}".strip()
    if not ok:
        out["overall_success"] = False
        if upload.get("summary"):
            out["summary"] = upload["summary"]
        if upload.get("hint"):
            out["hint"] = upload["hint"]
    return out
