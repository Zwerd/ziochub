"""
Trellix Network Security (NX): wsapis YARA add/remove preset rows.

Admin stores appliance rows in ``automation_trellix_nx_targets``; this module expands them into
HTTP target dicts consumed by ``utils.yara_http_push`` (same shape as generic automation targets).
"""

from __future__ import annotations

import json
import re
from typing import Any, List

_WS_VER_RE = re.compile(r"^v\d+\.\d+\.\d+$", re.IGNORECASE)


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


def expand_trellix_nx_targets(entries: Any) -> List[dict]:
    """Turn Integrations NX rows into generic YARA HTTP appliance dicts."""
    if not isinstance(entries, list):
        return []
    out: List[dict] = []
    for raw in entries:
        if not isinstance(raw, dict):
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
