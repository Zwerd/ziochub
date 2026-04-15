"""
Trellix Email Security (EX): YARA upload via session cookie after JSON password auth.

Upload (multipart POST):
  yara_file (binary), f_type, content_type (defaults: common / all)

Auth (JSON POST to configurable path):
  {"auth_method": "password", "data": {"username": "...", "password": "..."}}

Optional: skip login when admin sets a manual Cookie value (e.g. existing session_id).
"""

from __future__ import annotations

import json
import logging
import random
import ssl
import string
import urllib.error
import urllib.request
from typing import Any, Callable, List, Optional

from utils.yara_http_push import _evaluate_http_response_body, _truncate_msg

_MAX_RESPONSE_BODY_BYTES = 256 * 1024


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
        'login_path': (get_setting('trellix_ex_login_path', '/ex/login') or '/ex/login').strip(),
        'upload_path': (get_setting('trellix_ex_upload_path', '/ex/yara_rules_ng/upload_yara') or '').strip(),
        'username': (get_setting('trellix_ex_username', '') or '').strip(),
        'password': get_setting('trellix_ex_password', '') or '',
        'manual_cookie': (get_setting('trellix_ex_manual_cookie', '') or '').strip(),
        'verify_ssl': _verify_ssl_from_settings(get_setting),
        'f_type': (get_setting('trellix_ex_f_type', 'common') or 'common').strip(),
        'content_type': (get_setting('trellix_ex_content_type', 'all') or 'all').strip(),
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
    login_path = (r.get('login_path') or '').strip() or (get_setting('trellix_ex_login_path', '/ex/login') or '/ex/login').strip()
    upload_path = (r.get('upload_path') or '').strip() or (
        get_setting('trellix_ex_upload_path', '/ex/yara_rules_ng/upload_yara') or ''
    ).strip()
    if upload_path and not upload_path.startswith('/'):
        upload_path = '/' + upload_path
    username = (r.get('username') or '').strip()
    password = str(r.get('password') or '')
    manual_raw = r.get('manual_cookie')
    manual_cookie = (manual_raw if isinstance(manual_raw, str) else str(manual_raw or '')).strip()
    verify_ssl = _coerce_verify_ssl(r.get('verify_ssl'), _verify_ssl_from_settings(get_setting))
    f_type = (r.get('f_type') or '').strip() or (get_setting('trellix_ex_f_type', 'common') or 'common').strip() or 'common'
    ct = (r.get('content_type') or '').strip() or (get_setting('trellix_ex_content_type', 'all') or 'all').strip() or 'all'
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


def list_trellix_ex_upload_urls(get_setting: Callable[[str, str], str]) -> List[str]:
    out: List[str] = []
    for t in list_trellix_ex_targets(get_setting):
        u = trellix_ex_upload_url_for_target(t)
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
    up = (get_setting("trellix_ex_upload_path", "/ex/yara_rules_ng/upload_yara") or "").strip()
    if not up.startswith("/"):
        up = "/" + up
    return _join_url(base, up) if base else ""


def trellix_ex_enabled(get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting("trellix_ex_enabled", "false") or "false").lower() in ("true", "1", "yes")


def _verify_ssl_from_settings(get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting("trellix_ex_verify_ssl", "true") or "true").lower() in ("true", "1", "yes")


def _collect_set_cookie_values(resp: urllib.response.addinfourl) -> str:
    """Build a single Cookie header value from Set-Cookie response headers."""
    pairs: list[str] = []
    # get_all exists on HTTPMessage in modern Python
    try:
        raw_list = resp.headers.get_all("Set-Cookie")  # type: ignore[attr-defined]
    except Exception:
        raw_list = None
    if raw_list:
        for raw in raw_list:
            if not raw:
                continue
            first = raw.split(";", 1)[0].strip()
            if first and "=" in first:
                pairs.append(first)
        return "; ".join(pairs)
    # Fallback: single header line
    one = resp.headers.get("Set-Cookie")
    if one:
        first = one.split(";", 1)[0].strip()
        if first and "=" in first:
            return first
    return ""


def _normalize_manual_cookie(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    low = s.lower()
    if low.startswith("cookie:"):
        s = s.split(":", 1)[1].strip()
    return s


def trellix_ex_login_for_target(
    target: dict,
    *,
    verify_ssl: Optional[bool] = None,
) -> tuple[bool, str, str]:
    """
    JSON password login for one resolved target dict. Returns (ok, cookie_header_or_empty, message).
    """
    manual = _normalize_manual_cookie(target.get("manual_cookie") or "")
    if manual:
        return True, manual, "Using manual Cookie (login skipped)"

    base = (target.get("base_url") or "").strip().rstrip("/")
    if not base:
        return False, "", "Missing Trellix EX base URL"
    login_path = (target.get("login_path") or "/ex/login").strip()
    url = _join_url(base, login_path)
    user = (target.get("username") or "").strip()
    password = str(target.get("password") or "")
    if not user:
        return False, "", "Missing Trellix EX username"
    if not (password or "").strip():
        return False, "", "Missing Trellix EX password (or set a manual Cookie)"

    if verify_ssl is None:
        verify_ssl = bool(target.get("verify_ssl", True))

    body_obj = {"auth_method": "password", "data": {"username": user, "password": password}}
    body = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
    ctx = _ssl_context(verify_ssl)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    req.add_header("Accept", "application/json, */*;q=0.8")
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            code = resp.getcode()
            cookie = _collect_set_cookie_values(resp)
            body_bytes = b""
            try:
                body_bytes = resp.read(_MAX_RESPONSE_BODY_BYTES)
            except Exception:
                pass
            if not (200 <= code < 300):
                return False, "", f"Login HTTP {code}"
            logical_ok, detail = _evaluate_http_response_body(code, body_bytes)
            if not logical_ok:
                return False, cookie, detail or f"Login HTTP {code} rejected"
            if not cookie:
                logging.warning("Trellix EX login: no Set-Cookie in response; upload may fail without manual Cookie")
            return True, cookie, detail or "Login OK"
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            eb = e.read()
            if eb:
                err_body = eb.decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
        return False, "", _truncate_msg(f"Login HTTP {e.code} {e.reason}; {err_body}")
    except urllib.error.URLError as e:
        return False, "", str(e.reason or e)
    except Exception as e:
        logging.exception("Trellix EX login")
        return False, "", str(e)


def trellix_ex_login(
    get_setting: Callable[[str, str], str],
    *,
    verify_ssl: Optional[bool] = None,
) -> tuple[bool, str, str]:
    """Login for the first configured target (backward compatible)."""
    tgts = list_trellix_ex_targets(get_setting)
    if not tgts:
        return False, "", "No Trellix EX targets configured"
    t0 = tgts[0]
    vs = verify_ssl if verify_ssl is not None else bool(t0.get("verify_ssl", True))
    return trellix_ex_login_for_target(t0, verify_ssl=vs)


def _multipart_body(
    filename: str,
    content: str,
    f_type: str,
    content_type_val: str,
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
            "results": [{"name": name, "url": "", "success": False, "message": "Missing Trellix EX base URL"}],
        }

    vs = verify_ssl if verify_ssl is not None else bool(target.get("verify_ssl", True))
    if not vs:
        logging.warning("Trellix EX YARA push (%s): TLS certificate verification is disabled", name)

    f_type = (target.get("f_type") or "common").strip() or "common"
    ct_val = (target.get("content_type") or "all").strip() or "all"

    cookie = (cookie_header or "").strip()
    if not cookie:
        ok_login, cookie, login_msg = trellix_ex_login_for_target(target, verify_ssl=vs)
        if not ok_login:
            audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} login={login_msg[:300]}")
            return {
                "overall_success": False,
                "results": [{"name": name, "url": upload_url, "success": False, "message": login_msg}],
            }

    boundary, body = _multipart_body(filename, content, f_type, ct_val)
    ctx = _ssl_context(vs)
    req = urllib.request.Request(upload_url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Cookie", cookie)
    req.add_header("Accept", "*/*")

    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
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
                return {
                    "overall_success": logical_ok,
                    "results": [{"name": name, "url": upload_url, "success": logical_ok, "message": detail_msg}],
                }
            audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} code={code}")
            return {
                "overall_success": False,
                "results": [{"name": name, "url": upload_url, "success": False, "message": f"HTTP {code}"}],
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
        return {"overall_success": False, "results": [{"name": name, "url": upload_url, "success": False, "message": msg}]}
    except urllib.error.URLError as e:
        audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} error={e.reason}")
        return {
            "overall_success": False,
            "results": [{"name": name, "url": upload_url, "success": False, "message": str(e.reason or e)}],
        }
    except Exception as e:
        logging.exception("Trellix EX YARA push")
        audit_log_fn("yara_push_fail", f"file={filename} target=EX name={name} error={e}")
        return {"overall_success": False, "results": [{"name": name, "url": upload_url, "success": False, "message": str(e)}]}


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
    if not audit_log_fn:
        def _noop(*_a, **_k):
            pass

        audit_log_fn = _noop

    targets = list_trellix_ex_targets(get_setting)
    if not targets:
        audit_log_fn("yara_push_skip", "target=Trellix_EX reason=no_targets")
        return {
            "overall_success": False,
            "results": [{"name": "Trellix EX", "url": "", "success": False, "message": "No Trellix EX targets configured"}],
        }

    results: list[dict[str, Any]] = []
    overall = True
    shared = (cookie_header or "").strip()
    n = len(targets)
    for i, t in enumerate(targets):
        ck = shared if (shared and n == 1) else None
        one = _push_yara_trellix_ex_one(
            content, filename, t, audit_log_fn, verify_ssl=verify_ssl, cookie_header=ck
        )
        row = (one.get("results") or [{}])[0]
        results.append(row)
        overall = overall and bool(one.get("overall_success"))

    return {"overall_success": overall, "results": results}


def test_trellix_ex_connection(get_setting: Callable[[str, str], str], *, verify_ssl: Optional[bool] = None) -> dict[str, Any]:
    """Admin test: login + POST minimal safe YARA (same as FireEye test rule shape)."""
    _test_yara = """rule ziochub_connection_test {
    meta:
        description = "ZIoCHub connectivity test (safe; condition is false)"
    condition:
        false
}
"""

    if not trellix_ex_enabled(get_setting):
        return {"success": False, "message": "Trellix EX is disabled. Enable it or use Save first.", "overall_success": False, "results": []}
    if not list_trellix_ex_targets(get_setting):
        return {
            "success": True,
            "overall_success": False,
            "results": [],
            "message": "Add at least one EX target with a base URL, then save.",
        }
    res = push_yara_trellix_ex(
        _test_yara,
        "ziochub_connection_test.yar",
        get_setting,
        audit_log_fn=lambda *a, **k: None,
        verify_ssl=verify_ssl,
    )
    ok = bool(res.get("overall_success"))
    msgs = []
    for r in res.get("results") or []:
        if isinstance(r, dict) and (r.get("message") or "").strip():
            msgs.append(str(r.get("message") or "").strip())
    msg = "; ".join(msgs)[:900] if msgs else ""
    return {"success": True, "overall_success": ok, "results": res.get("results", []), "message": msg}
