"""
IOC tags: normalize to lowercase, dedupe, cap count (shared by API routes).
"""
from __future__ import annotations

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
