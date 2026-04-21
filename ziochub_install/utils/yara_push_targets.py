"""
Merge YARA automation: optional Trellix NX presets + generic HTTP targets.

NX rows are expanded in ``utils.trellix_nx``. Generic targets use the historical setting key
``automation_fireeye_appliances`` (vendor-neutral HTTP list; name kept for DB compatibility).
"""

from __future__ import annotations

import json
from typing import Any, Callable, List

from utils.trellix_nx import expand_trellix_nx_targets, parse_trellix_nx_targets_json


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
