"""
Merge YARA automation: optional Trellix NX presets + generic HTTP targets.

NX **wsapis** rows are expanded in ``utils.trellix_nx``; **wmps** rows use session push there and are not merged here. Generic targets use the historical setting key
``automation_fireeye_appliances`` (vendor-neutral HTTP list; name kept for DB compatibility).
"""

from __future__ import annotations

import json
from typing import Any, Callable, List, Optional

from utils.trellix_nx import expand_trellix_nx_targets, parse_trellix_nx_targets_json


def yara_http_push_verify_ssl(get_setting: Callable[[str, str], str]) -> bool:
    """Global TLS verify flag for generic HTTP / NX wsapis YARA push (``automation_fireeye_ignore_ssl``)."""
    return (get_setting('automation_fireeye_ignore_ssl', 'false') or 'false').lower() != 'true'


def yara_session_push_verify_ssl(get_setting: Callable[[str, str], str]) -> Optional[bool]:
    """TLS verify for Trellix EX / NX wmps (approve, delete, retry).

    When ``automation_fireeye_ignore_ssl`` is on, verification is off for all session targets.
    Otherwise ``None`` so each target row's ``verify_ssl`` applies (same as Integrations test).
    """
    if (get_setting('automation_fireeye_ignore_ssl', 'false') or 'false').lower() == 'true':
        return False
    return None


def merged_yara_automation_appliances(get_setting: Callable[[str, str], str]) -> List[dict]:
    merged: List[dict] = []
    if get_setting("automation_trellix_nx_enabled", "false").lower() == "true":
        raw_t = get_setting("automation_trellix_nx_targets", "[]") or "[]"
        merged.extend(expand_trellix_nx_targets(parse_trellix_nx_targets_json(raw_t)))

    raw_g = get_setting("automation_fireeye_appliances", "[]") or "[]"
    try:
        generic = json.loads(raw_g) if isinstance(raw_g, str) else raw_g
    except (json.JSONDecodeError, TypeError, ValueError):
        generic = []
    if isinstance(generic, list):
        merged.extend([a for a in generic if isinstance(a, dict)])
    return merged
