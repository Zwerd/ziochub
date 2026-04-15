"""
IOC tags: normalize to lowercase, dedupe, cap count (shared by API routes).
"""
from __future__ import annotations

import json
from typing import Any

MAX_TAGS = 50


def normalize_tags_from_input(tags_raw: Any) -> list[str]:
    """
    Parse tags from JSON body (list or comma-separated string).
    Strip whitespace, lowercase each tag, dedupe preserving first-seen order, max MAX_TAGS.
    """
    if tags_raw is None:
        return []
    if isinstance(tags_raw, list):
        parts = [str(t).strip() for t in tags_raw]
    elif isinstance(tags_raw, str):
        parts = [t.strip() for t in tags_raw.split(',')]
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        if not p:
            continue
        low = p.lower()
        if low not in seen:
            seen.add(low)
            out.append(low)
        if len(out) >= MAX_TAGS:
            break
    return out


def parse_allowed_tags_setting(raw: str | None) -> list[str]:
    """
    Parse system setting `allowed_tags` (JSON list or comma-separated string).
    Returns a normalized (lowercased, deduped) list.
    """
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []
    # Prefer JSON array if provided
    if s.startswith('['):
        try:
            data = json.loads(s)
            return normalize_tags_from_input(data)
        except Exception:
            return []
    return normalize_tags_from_input(s)


def enforce_allowed_tags(tags_list: list[str], allowed_tags: list[str]) -> tuple[list[str], list[str]]:
    """
    Given normalized tags_list and normalized allowed_tags, return (valid, invalid).
    Does not modify order of tags_list.
    """
    allowed_set = set((t or '').strip().lower() for t in (allowed_tags or []) if (t or '').strip())
    invalid = [t for t in (tags_list or []) if (t or '').strip().lower() not in allowed_set] if allowed_set else []
    valid = [t for t in (tags_list or []) if (t or '').strip().lower() in allowed_set] if allowed_set else list(tags_list or [])
    return valid, invalid
