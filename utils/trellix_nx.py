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

from utils.trellix_ex import (
    delete_yara_session_targets,
    push_yara_session_targets,
    trellix_ex_delete_url_for_target,
    trellix_ex_upload_url_for_target,
)

_WS_VER_RE = re.compile(r"^v\d+\.\d+\.\d+$", re.IGNORECASE)

_DEFAULT_NX_WMPS_UPLOAD = "/wmps/yara_rules_ng/upload_yara"
_DEFAULT_SESSION_LOGIN = "/login/login"
_DEFAULT_WMPS_CONTENT_TYPE = "base"


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
    f_type = (r.get("f_type") or "common").strip() or "common"
    ct = (r.get("content_type") or "").strip() or _DEFAULT_WMPS_CONTENT_TYPE
    csrf_param = (r.get("csrf_param") or "").strip()
    csrf_token = (r.get("csrf_token") or "").strip()
    delete_path = (r.get("delete_path") or "").strip()
    ex_delete_name_mode = (r.get("ex_delete_name_mode") or "same").strip().lower()
    if ex_delete_name_mode not in ("same", "yar_txt"):
        ex_delete_name_mode = "same"
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
    }


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
