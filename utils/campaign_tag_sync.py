"""
Merge campaign-level tags onto IOC rows and record IocHistory (edited / tags).

Campaign tags are stored on Campaign.tags (JSON array). When new tags are added
to a campaign, they are merged (never replacing existing IOC tags). Unlinking
an IOC from a campaign does not remove tags the IOC already had.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

from models import IOC, Campaign, _utcnow

logger = logging.getLogger(__name__)


def merge_campaign_tags_into_tags_json(tags_field: Any, campaign_id: int | None) -> str:
    """
    Merge Campaign.tags onto an IOC tags JSON field when campaign_id is set.
    Uses Flask db session. Returns JSON array string for IOC.tags.
    """
    cur = parse_tags_field(tags_field)
    if not campaign_id:
        return json.dumps(cur) if cur else '[]'
    try:
        from extensions import db
    except Exception:
        return json.dumps(cur) if cur else '[]'
    camp = db.session.get(Campaign, int(campaign_id))
    if not camp:
        return json.dumps(cur) if cur else '[]'
    ctags = parse_tags_field(getattr(camp, 'tags', None))
    merged, _ = merge_tag_lists(cur, ctags)
    return json.dumps(merged) if merged else '[]'


def parse_tags_field(tags_field: Any) -> list[str]:
    if not tags_field:
        return []
    try:
        data = json.loads(tags_field) if isinstance(tags_field, str) else tags_field
        if not isinstance(data, list):
            return []
        return [str(t).strip().lower() for t in data if str(t).strip()]
    except (TypeError, ValueError):
        return []


def merge_tag_lists(existing: list[str], to_add: list[str]) -> tuple[list[str], list[str]]:
    """
    Lowercase dedupe merge: existing order preserved, then append new tags not yet present.
    Returns (merged_list, newly_added_tags) where newly_added preserves order of to_add.
    """
    seen = {t.lower() for t in (existing or []) if t}
    out = list(existing or [])
    added: list[str] = []
    for t in to_add or []:
        if not t:
            continue
        low = t.strip().lower()
        if not low:
            continue
        if low not in seen:
            seen.add(low)
            out.append(low)
            added.append(low)
    return out, added


def apply_tags_merge_to_ioc(
    ioc: IOC,
    tags_to_merge: list[str],
    username: str | None,
    _log_ioc_history: Callable[..., None],
    *,
    source: str = 'campaign_tags',
    extra_payload: dict | None = None,
) -> bool:
    """
    Merge tags_to_merge into ioc.tags. Logs one 'edited' IocHistory row if tags changed.
    Sets modified_at. Returns True if IOC was updated.
    """
    old_list = parse_tags_field(ioc.tags)
    merged, added = merge_tag_lists(old_list, tags_to_merge)
    if not added:
        return False
    old_display = ', '.join(old_list) if old_list else ''
    new_display = ', '.join(merged) if merged else ''
    ioc.tags = json.dumps(merged)
    ioc.modified_at = _utcnow()
    payload: dict[str, Any] = {
        'changes': [{'field': 'tags', 'old': old_display or '\u2014', 'new': new_display or '\u2014'}],
        'source': source,
    }
    if extra_payload:
        payload.update(extra_payload)
    try:
        _log_ioc_history(
            ioc.type,
            (ioc.value or '').strip(),
            'edited',
            username,
            payload,
        )
    except Exception:
        logger.exception('apply_tags_merge_to_ioc: _log_ioc_history failed')
    return True


def sync_added_tags_to_campaign_iocs(
    campaign_id: int,
    added_tags: list[str],
    username: str | None,
    _log_ioc_history: Callable[..., None],
) -> int:
    """
    For every IOC linked to campaign_id, merge added_tags into IOC.tags with history.
    Returns count of IOC rows updated.
    """
    if not added_tags:
        return 0
    n = 0
    rows = IOC.query.filter(IOC.campaign_id == campaign_id).all()
    for ioc in rows:
        if apply_tags_merge_to_ioc(
            ioc,
            added_tags,
            username,
            _log_ioc_history,
            source='campaign_tags',
            extra_payload={'campaign_id': campaign_id},
        ):
            n += 1
    return n
