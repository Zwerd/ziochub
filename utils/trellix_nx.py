"""
Trellix Network Security (NX): two integration styles for YARA automation.

1. **wsapis** (default): REST preset rows expanded into HTTP target dicts for
   ``utils.yara_http_push`` (API key + ``/wsapis/{ver}/customioc/yara/...``).

2. **wmps**: Web UI session flow (same multipart / delete shape as Email EX but under
   ``/wmps/yara_rules_ng/...``). Rows use ``api_style: "wmps"`` plus the same fields as an EX
   target (``login_path``, ``upload_path``, credentials, CSRF overrides, etc.).
   Push/delete reuse ``push_yara_session_targets`` / ``delete_yara_session_targets`` in
   ``utils.trellix_ex``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable, List, Optional

import logging
import urllib.request

from utils.trellix_ex import (
    _DEFAULT_EX_LOGIN_PATH,
    _EX_ACCEPT,
    _EX_CONNECTION_TEST_FILENAME,
    _EX_CONNECTION_TEST_YARA,
    _ExAuthResult,
    _aggregate_step_messages,
    _apply_ex_browser_headers,
    _ex_authenticate_for_target,
    _ex_open,
    _join_url,
    _step_response,
    _trellix_ex_operator_hint,
    delete_yara_session_targets,
    push_yara_session_targets,
    trellix_ex_delete_url_for_target,
    trellix_ex_upload_url_for_target,
)

_WS_VER_RE = re.compile(r"^v\d+\.\d+\.\d+$", re.IGNORECASE)

_DEFAULT_NX_WMPS_UPLOAD = "/wmps/yara_rules_ng/upload_yara"
_DEFAULT_NX_WMPS_DELETE = "/wmps/yara_rules_ng/delete_yara_files"
_DEFAULT_SESSION_LOGIN = "/login/login"
_DEFAULT_WMPS_CONTENT_TYPE = "base"
# NX web UI (wmps) uses f_type=txt on upload/delete (not EX "common").
_DEFAULT_NX_WMPS_F_TYPE = "txt"
_WMPS_WARMUP_PATHS = (
    ("/wmps/yara_rules_ng/get_file_types", "get_file_types"),
    ("/wmps/yara_rules_ng/get_yara_files?offset=0&num=25", "get_yara_files"),
    ("/wmps/yara_rules_ng/get_error_types", "get_error_types"),
)


def _normalize_wsapis_version(raw: str) -> str:
    s = (raw or "").strip()
    if not s or "/" in s or "\\" in s:
        return "v2.0.0"
    if not s.lower().startswith("v"):
        s = "v" + s
    if _WS_VER_RE.match(s):
        return s
    return "v2.0.0"


def _normalize_yara_file_type(raw: str) -> str:
    ft = (raw or "yar").strip().lower()
    if not ft or not re.match(r"^[a-z0-9_]+$", ft):
        return "yar"
    return ft


def _nx_api_style(raw: dict) -> str:
    return (raw.get("api_style") or "wsapis").strip().lower()


def _coerce_verify_ssl(val: Any, fallback: bool) -> bool:
    if val is None:
        return fallback
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return bool(val)


def normalize_nx_wmps_target_row(r: dict) -> Optional[dict]:
    """One session-style target dict for NX wmps (same keys as EX rows for trellix_ex helpers)."""
    base_url = (r.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        return None
    name = (r.get("name") or "").strip() or "Trellix NX (wmps)"
    login_path = (r.get("login_path") or "").strip() or _DEFAULT_SESSION_LOGIN
    upload_path = (r.get("upload_path") or "").strip() or _DEFAULT_NX_WMPS_UPLOAD
    if upload_path and not upload_path.startswith("/"):
        upload_path = "/" + upload_path
    username = (r.get("username") or "").strip()
    password = str(r.get("password") or "")
    manual_raw = r.get("manual_cookie")
    manual_cookie = (manual_raw if isinstance(manual_raw, str) else str(manual_raw or "")).strip()
    verify_ssl = _coerce_verify_ssl(r.get("verify_ssl"), True)
    f_type = (r.get("f_type") or "").strip() or _DEFAULT_NX_WMPS_F_TYPE
    ct = (r.get("content_type") or "").strip() or _DEFAULT_WMPS_CONTENT_TYPE
    csrf_param = (r.get("csrf_param") or "").strip()
    csrf_token = (r.get("csrf_token") or "").strip()
    delete_path = (r.get("delete_path") or "").strip() or _DEFAULT_NX_WMPS_DELETE
    ex_delete_name_mode = (r.get("ex_delete_name_mode") or "same").strip().lower()
    if ex_delete_name_mode not in ("same", "yar_txt"):
        ex_delete_name_mode = "same"
    auth_method = (r.get("auth_method") or "auto").strip().lower()
    if auth_method not in ("password", "ldap", "auto"):
        auth_method = "auto"
    wmps_warmup = r.get("wmps_warmup", True)
    if isinstance(wmps_warmup, str):
        wmps_warmup = wmps_warmup.strip().lower() in ("true", "1", "yes")
    else:
        wmps_warmup = bool(wmps_warmup)
    return {
        "name": name,
        "base_url": base_url,
        "login_path": login_path,
        "upload_path": upload_path,
        "username": username,
        "password": password,
        "manual_cookie": manual_cookie,
        "verify_ssl": verify_ssl,
        "f_type": f_type,
        "content_type": ct,
        "csrf_param": csrf_param,
        "csrf_token": csrf_token,
        "delete_path": delete_path,
        "ex_delete_name_mode": ex_delete_name_mode,
        "auth_method": auth_method,
        "wmps_warmup": wmps_warmup,
        "product_name": "Trellix NX (wmps)",
    }


def wmps_yara_ui_warmup(auth: _ExAuthResult, target: dict) -> list[dict[str, Any]]:
    """
    Optional GETs the NX YARA UI performs before upload (CSRF/session priming).
    Returns per-endpoint rows for test logging; failures are non-fatal for push.
    """
    base = (target.get("base_url") or "").strip().rstrip("/")
    if not base:
        return []
    referer = _join_url(base, "/wmps/settings/yara_rules")
    csrf_p = (target.get("csrf_param") or "").strip() or "authenticity_token"
    csrf_t = (target.get("csrf_token") or "").strip()
    rows: list[dict[str, Any]] = []
    for path, label in _WMPS_WARMUP_PATHS:
        url = _join_url(base, path)
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", _EX_ACCEPT)
        req.add_header("X-Requested-With", "XMLHttpRequest")
        if csrf_t:
            req.add_header("X-CSRF-Token", csrf_t)
            req.add_header("X-CSRF-Param", csrf_p)
        _apply_ex_browser_headers(req, base_url=base, referer=referer)
        if auth.opener is None and auth.cookie_header:
            req.add_header("Cookie", auth.cookie_header)
        try:
            with _ex_open(auth, req, timeout=30) as resp:
                code = resp.getcode()
                rows.append({
                    "endpoint": label,
                    "url": url,
                    "success": 200 <= code < 300,
                    "http_status": code,
                    "message": f"HTTP {code}",
                })
        except Exception as e:
            rows.append({
                "endpoint": label,
                "url": url,
                "success": False,
                "message": str(e),
            })
    return rows


def expand_trellix_nx_targets(entries: Any) -> List[dict]:
    """Turn Integrations NX rows into generic YARA HTTP appliance dicts (wsapis only; wmps excluded)."""
    if not isinstance(entries, list):
        return []
    out: List[dict] = []
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        if _nx_api_style(raw) == "wmps":
            continue
        name = (raw.get("name") or "").strip() or "Trellix NX"
        base = (raw.get("base_url") or "").strip().rstrip("/")
        if not base:
            continue
        ver = _normalize_wsapis_version(raw.get("wsapis_version") or "")
        ft = _normalize_yara_file_type(raw.get("yara_file_type") or "")
        path = f"/wsapis/{ver}/customioc/yara/add/{ft}"
        delete_path = f"/wsapis/{ver}/customioc/yara/remove/{ft}/{{filename}}"
        out.append(
            {
                "name": name,
                "base_url": base,
                "path": path,
                "delete_path": delete_path,
                "delete_http_method": "POST",
                "api_key": (raw.get("api_key") or "").strip(),
                "api_key_header": (raw.get("api_key_header") or "").strip(),
            }
        )
    return out


def parse_trellix_nx_targets_json(raw: str | Any) -> list:
    """Parse ``automation_trellix_nx_targets`` setting into a list (or [])."""
    if isinstance(raw, list):
        return raw
    try:
        data = json.loads((raw or "").strip() or "[]")
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, TypeError, ValueError):
        return []


def trellix_nx_enabled(get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting("automation_trellix_nx_enabled", "false") or "false").lower() in ("true", "1", "yes")


def list_nx_wmps_session_targets(get_setting: Callable[[str, str], str]) -> List[dict]:
    """Resolved wmps session targets (empty if NX automation disabled or no wmps rows)."""
    if not trellix_nx_enabled(get_setting):
        return []
    out: List[dict] = []
    for raw in parse_trellix_nx_targets_json(get_setting("automation_trellix_nx_targets", "[]")):
        if not isinstance(raw, dict):
            continue
        if _nx_api_style(raw) != "wmps":
            continue
        t = normalize_nx_wmps_target_row(raw)
        if t:
            out.append(t)
    return out


def trellix_nx_wmps_enabled(get_setting: Callable[[str, str], str]) -> bool:
    return bool(list_nx_wmps_session_targets(get_setting))


def list_nx_wmps_upload_urls(get_setting: Callable[[str, str], str]) -> List[str]:
    urls: List[str] = []
    for t in list_nx_wmps_session_targets(get_setting):
        u = trellix_ex_upload_url_for_target(t)
        if u:
            urls.append(u)
    return urls


def list_nx_wmps_delete_urls(get_setting: Callable[[str, str], str]) -> List[str]:
    urls: List[str] = []
    for t in list_nx_wmps_session_targets(get_setting):
        u = trellix_ex_delete_url_for_target(t)
        if u:
            urls.append(u)
    return urls


def push_yara_nx_wmps(
    content: str,
    filename: str,
    get_setting: Callable[[str, str], str],
    audit_log_fn=None,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict:
    targets = list_nx_wmps_session_targets(get_setting)
    return push_yara_session_targets(
        content,
        filename,
        targets,
        audit_log_fn,
        verify_ssl=verify_ssl,
        cookie_header=cookie_header,
        empty_skip_log="yara_push_skip",
        empty_log_detail="target=NX_wmps reason=no_targets",
        empty_result_name="Trellix NX (wmps)",
        empty_message="No Trellix NX wmps targets (set api_style to wmps and base_url)",
    )


def delete_yara_nx_wmps(
    filename: str,
    get_setting: Callable[[str, str], str],
    audit_log_fn=None,
    *,
    verify_ssl: Optional[bool] = None,
    cookie_header: Optional[str] = None,
) -> dict:
    targets = list_nx_wmps_session_targets(get_setting)
    return delete_yara_session_targets(
        filename,
        targets,
        audit_log_fn,
        verify_ssl=verify_ssl,
        cookie_header=cookie_header,
        empty_skip_log="yara_delete_skip",
        empty_log_detail="target=NX_wmps reason=no_targets",
        empty_result_name="Trellix NX (wmps)",
        empty_message="No Trellix NX wmps targets (set api_style to wmps and base_url)",
    )


def _test_nx_wmps_precheck(get_setting: Callable[[str, str], str]) -> Optional[dict[str, Any]]:
    if not trellix_nx_enabled(get_setting):
        return {
            "success": False,
            "overall_success": False,
            "results": [],
            "headline": "Trellix NX automation is disabled.",
            "summary": "Enable Include NX appliances in YARA automation, save, then test again.",
            "message": "automation_trellix_nx_enabled is false.",
        }
    targets = list_nx_wmps_session_targets(get_setting)
    if not targets:
        return {
            "success": True,
            "overall_success": False,
            "results": [],
            "headline": "No Trellix NX wmps targets configured.",
            "summary": "Add an NX row with API style wmps and base URL, save, then test.",
            "message": "No wmps rows in automation_trellix_nx_targets.",
        }
    return None


def test_trellix_nx_wmps_step(
    get_setting: Callable[[str, str], str],
    step: str,
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    """Staged NX wmps test: auth (login + optional UI warmup) | upload | cleanup."""
    step_l = (step or "").strip().lower()
    pre = _test_nx_wmps_precheck(get_setting)
    if pre:
        pre["step"] = step_l
        return pre

    targets = list_nx_wmps_session_targets(get_setting)
    n = len(targets)

    if step_l == "auth":
        rows = []
        for t in targets:
            name = (t.get("name") or "Trellix NX (wmps)").strip()
            vs = verify_ssl if verify_ssl is not None else bool(t.get("verify_ssl", True))
            auth = _ex_authenticate_for_target(t, verify_ssl=vs)
            warmup_detail = ""
            if auth.ok and t.get("wmps_warmup", True):
                warm = wmps_yara_ui_warmup(auth, t)
                if warm:
                    failed = [w for w in warm if not w.get("success")]
                    warmup_detail = "; warmup: " + ", ".join(
                        f"{w.get('endpoint')}={w.get('http_status') or w.get('message')}" for w in warm
                    )
                    if failed:
                        warmup_detail += f" ({len(failed)} warmup GET(s) non-2xx)"
            login_url = _join_url(
                (t.get("base_url") or "").strip().rstrip("/"),
                (t.get("login_path") or _DEFAULT_EX_LOGIN_PATH).strip(),
            )
            hint = ""
            if not auth.ok:
                hint = _trellix_ex_operator_hint(phase="login", message=auth.message)
            row = {
                "name": name,
                "url": login_url,
                "success": auth.ok,
                "phase": "login",
                "summary": "Authentication succeeded." if auth.ok else "Authentication failed.",
                "message": (auth.message or "") + warmup_detail,
                "hint": hint or None,
            }
            rows.append(row)
        ok = bool(rows) and all(r.get("success") for r in rows)
        msg, hint, summ = _aggregate_step_messages(rows)
        if ok:
            headline = "Authentication completed successfully"
            subline = f"Session established for {n} NX wmps target{'s' if n != 1 else ''} (login + YARA UI warmup)."
        else:
            headline = "Authentication failed"
            subline = "Could not log in to one or more NX wmps targets."
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
        res = push_yara_nx_wmps(
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
            subline = f"Uploaded {fn} via wmps to {n} target{'s' if n != 1 else ''} (f_type=txt, content_type=base)."
        else:
            headline = "Test rule upload failed"
            subline = f"Could not upload {fn} to all NX wmps targets."
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
        res = delete_yara_nx_wmps(
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
            subline = f"Removed {fn} from {n} NX wmps target{'s' if n != 1 else ''}."
        else:
            headline = "Test rule cleanup failed"
            subline = f"{fn} may still be on the appliance."
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


def test_trellix_nx_wmps_connection(
    get_setting: Callable[[str, str], str],
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    pre = _test_nx_wmps_precheck(get_setting)
    if pre:
        return pre
    all_results: list[dict[str, Any]] = []
    overall = True
    last_headline = ""
    for st in ("auth", "upload", "cleanup"):
        one = test_trellix_nx_wmps_step(get_setting, st, verify_ssl=verify_ssl)
        last_headline = one.get("headline") or last_headline
        all_results.extend(one.get("results") or [])
        overall = overall and bool(one.get("overall_success"))
    return {
        "success": True,
        "overall_success": overall,
        "results": all_results,
        "headline": last_headline or ("OK" if overall else "NX wmps test failed"),
        "message": "Combined NX wmps test.",
    }
