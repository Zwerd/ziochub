"""
Search & Investigate routes: search, IOC history/notes, edit, revoke, export, recent.
Blueprint registered with url_prefix=None so routes keep their original /api/… paths.
"""
import json
import csv
import io
import logging
import os
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, Response
from flask_login import current_user
from sqlalchemy import func, cast, String, text, case
from sqlalchemy.orm import joinedload, aliased

from extensions import db
from models import Campaign, IOC, IocHistory, IocNote, YaraRule, User, UserProfile, _utcnow, iso_utc
from utils.decorators import login_required
from utils.refanger import refanger, sanitize_comment
from utils.validation import validate_ioc
from utils.validation_messages import (
    MSG_MISSING_FIELDS_TYPE_VALUE,
    MSG_INVALID_IOC_TYPE,
    MSG_IOC_NOT_FOUND,
)
from constants import IOC_FILES, DEFAULT_PAGE_SIZE, DEFAULT_IOC_LIMIT
from utils.tags import normalize_tags_from_input
from utils.tags import parse_allowed_tags_setting, enforce_allowed_tags
from utils.campaign_tag_sync import merge_campaign_tags_into_tags_json, parse_tags_field

logger = logging.getLogger(__name__)

bp = Blueprint('search_bp', __name__)


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


def _strip_feed_identity_fields(item: dict) -> dict:
    """Remove analyst usernames from public feed payloads (Live Stats for anonymous viewers)."""
    out = dict(item)
    out['user'] = ''
    out['analyst'] = ''
    return out


def _maybe_strip_feed_identity(item: dict) -> dict:
    try:
        if current_user.is_authenticated:
            return item
    except Exception:
        pass
    return _strip_feed_identity_fields(item)


def _search_needles_from_query(query: str) -> list[str]:
    """Lowercased search needles: raw query plus refanger-cleaned variant when different."""
    raw = (query or '').strip()
    if not raw:
        return []
    needles: list[str] = []
    seen: set[str] = set()
    for candidate in (raw.lower(),):
        if candidate and candidate not in seen:
            seen.add(candidate)
            needles.append(candidate)
    try:
        cleaned, _ = refanger(raw)
        c = (cleaned or '').strip().lower()
        if c and c not in seen:
            seen.add(c)
            needles.append(c)
    except Exception:
        pass
    return needles


def _sql_value_matches_needles(column, needles: list[str]):
    """Case-insensitive substring match on trimmed value (SQLite-safe; no LIKE escape issues)."""
    if not needles:
        return False
    return db.or_(*[func.lower(func.trim(column)).contains(n) for n in needles])


def _ioc_value_text_matches_needles(row, needles: list[str]) -> bool:
    val = (row.value or '').strip().lower()
    if not val or not needles:
        return False
    return any(n in val for n in needles)


def _parse_search_lifecycle(raw: str) -> str:
    """``all`` (default), ``active``, or ``inactive`` — aligned with ``ioc_row_is_active``."""
    v = (raw or 'all').strip().lower()
    if v in ('active', 'inactive', 'all'):
        return v
    return 'all'


def _ioc_active_clause(now):
    return db.and_(
        IOC.revoked.is_(False),
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now),
    )


def _ioc_inactive_clause(now):
    return db.or_(
        IOC.revoked.is_(True),
        db.and_(IOC.expiration_date.isnot(None), IOC.expiration_date <= now),
    )


def _apply_search_lifecycle(q, lifecycle: str, now=None):
    lifecycle = _parse_search_lifecycle(lifecycle)
    if lifecycle == 'active':
        if now is None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
        return q.filter(_ioc_active_clause(now))
    if lifecycle == 'inactive':
        if now is None:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
        return q.filter(_ioc_inactive_clause(now))
    return q


def _lookup_ioc_rows_by_value_for_lifecycle(query: str, lifecycle: str) -> list:
    """Value lookup respecting Search lifecycle filter (fixes partial-match hiding deleted rows)."""
    lifecycle = _parse_search_lifecycle(lifecycle)
    (ioc_row_is_active,) = _from_app('ioc_row_is_active')
    if lifecycle == 'active':
        return _lookup_ioc_rows_by_value(query, include_inactive=False)
    all_matching = _lookup_ioc_rows_by_value(query, include_inactive=True)
    if lifecycle == 'inactive':
        return [r for r in all_matching if not ioc_row_is_active(r)]
    return all_matching


def _lookup_ioc_rows_by_value(query: str, *, include_inactive: bool = False) -> list:
    """
    Fast, reliable lookup by IOC value (exact trim match, then substring).
    When ``include_inactive`` is True, also returns revoked / TTL-expired rows (Search shows them
    with status Deleted/Expired even though plain feeds omit them).
    """
    needles = _search_needles_from_query(query)
    if not needles:
        return []
    seen_ids: set[int] = set()
    rows: list = []

    def _collect(q):
        for row in q.all():
            if row.id not in seen_ids:
                seen_ids.add(row.id)
                rows.append(row)

    base = IOC.query.options(joinedload(IOC.campaign))
    if not include_inactive:
        base = base.filter(IOC.revoked.is_(False))
    for n in needles:
        _collect(base.filter(func.lower(func.trim(IOC.value)) == n))
        _collect(base.filter(_sql_value_matches_needles(IOC.value, [n])))
    return rows


def _terminal_status_for_revoked_rows(rows) -> dict:
    """
    For revoked IOC rows, look up the most recent terminal event in ``ioc_history``
    (``deleted`` for manual revocation, ``expired`` for cleaner TTL revocation) and
    return ``{(ioc_type, value_lower): 'Deleted' | 'Expired'}``.

    Single SQL query (no N+1): pulls all matching history rows in one shot, ordered
    newest-first, and keeps only the first event per (type, value).
    """
    revoked_keys = []
    seen_keys: set = set()
    for r in rows or []:
        if not getattr(r, 'revoked', False):
            continue
        key = (r.type, (r.value or '').strip().lower())
        if key in seen_keys:
            continue
        seen_keys.add(key)
        revoked_keys.append(key)
    if not revoked_keys:
        return {}
    or_clauses = [
        db.and_(IocHistory.ioc_type == t, func.lower(IocHistory.ioc_value) == v)
        for (t, v) in revoked_keys
    ]
    hist_rows = (
        IocHistory.query
        .filter(IocHistory.event_type.in_(('deleted', 'expired')))
        .filter(db.or_(*or_clauses))
        .order_by(IocHistory.at.desc())
        .all()
    )
    status_map: dict = {}
    for h in hist_rows:
        key = (h.ioc_type, (h.ioc_value or '').strip().lower())
        if key in status_map:
            continue
        status_map[key] = 'Deleted' if h.event_type == 'deleted' else 'Expired'
    return status_map


def _apply_revoked_terminal_status(results: list, source_rows: list) -> None:
    """
    Mutate ``results`` in place: for every result whose underlying IOC row is revoked,
    set ``status``/``expiration_status`` to ``Deleted`` or ``Expired`` based on the most
    recent ``ioc_history`` event. Falls back to ``Expired`` when ``expiration_date`` is in
    the past, otherwise ``Deleted`` (covers cases where history is missing for legacy rows).
    """
    status_map = _terminal_status_for_revoked_rows(source_rows)
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    for d in results:
        row = next((r for r in source_rows if r.id == d.get('line_number')), None)
        if not row or not getattr(row, 'revoked', False):
            continue
        key = (row.type, (row.value or '').strip().lower())
        label = status_map.get(key)
        if not label:
            exp = getattr(row, 'expiration_date', None)
            label = 'Expired' if (exp is not None and exp < now_dt) else 'Deleted'
        d['status'] = label
        d['expiration_status'] = label


def terminal_status_label_for_ioc_row(row) -> str | None:
    """
    User-facing inactive label for a revoked IOC row: ``Deleted`` (manual removal) or ``Expired`` (TTL).
    Returns None when the row is still active. STIX/TAXII continue to use the ``revoked`` column internally.
    """
    if not row or not getattr(row, 'revoked', False):
        return None
    key = (row.type, (row.value or '').strip().lower())
    label = _terminal_status_for_revoked_rows([row]).get(key)
    if label:
        return label
    now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    exp = getattr(row, 'expiration_date', None)
    return 'Expired' if (exp is not None and exp < now_dt) else 'Deleted'


def _search_legacy_main_txt_for_value(query: str) -> list:
    """Scan data/Main/*.txt for lines containing the query (unmigrated legacy rows)."""
    try:
        import app as _app
        data_main = getattr(_app, 'DATA_MAIN', None)
        if not data_main or not os.path.isdir(data_main):
            return []
    except Exception:
        return []
    needles = _search_needles_from_query(query)
    if not needles:
        return []
    hits = []
    for ioc_type, filename in IOC_FILES.items():
        if ioc_type == 'YARA':
            continue
        path = os.path.join(data_main, filename)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    raw = line.strip()
                    if not raw:
                        continue
                    ll = raw.lower()
                    if not any(n in ll for n in needles):
                        continue
                    ioc_val = raw
                    try:
                        from app import _parse_ioc_line_permissive
                        parsed = _parse_ioc_line_permissive(raw)
                        if parsed and parsed.get('ioc'):
                            ioc_val = (parsed.get('ioc') or '').strip()
                    except Exception:
                        ioc_val = raw.split('#')[0].strip() if '#' in raw else raw
                    hits.append({
                        'ioc': ioc_val,
                        'value': ioc_val,
                        'file_type': ioc_type,
                        'date': None,
                        'user': '',
                        'ref': '',
                        'comment': '',
                        'expiration': 'NEVER',
                        'line_number': line_num,
                        'raw_line': raw,
                        'expiration_status': 'Legacy file',
                        'expires_on': None,
                        'is_expired': False,
                        'status': 'Legacy file only',
                        'campaign_name': None,
                        'tags': [],
                        'match_hints': ['legacy_file'],
                        'legacy_source': filename,
                    })
        except OSError:
            continue
    return hits


def _distinct_ioc_tags_from_db():
    """Return sorted list of distinct tag strings (lowercase) from iocs.tags JSON."""
    tags_set = set()
    try:
        rows = db.session.execute(
            text(
                """
                SELECT DISTINCT LOWER(TRIM(CAST(j.value AS TEXT))) AS tag
                FROM iocs AS i
                JOIN json_each(i.tags) AS j
                WHERE i.tags IS NOT NULL
                  AND TRIM(COALESCE(i.tags, '')) NOT IN ('', '[]')
                  AND LOWER(TRIM(CAST(j.value AS TEXT))) != ''
                """
            )
        ).fetchall()
        for (t,) in rows:
            if t:
                tags_set.add(t)
    except Exception:
        logger.debug('tags json_each failed, scanning iocs.tags rows', exc_info=True)
        for row in IOC.query.with_entities(IOC.tags).filter(IOC.tags.isnot(None)):
            raw = row[0]
            if not raw or raw == '[]':
                continue
            try:
                arr = json.loads(raw) if isinstance(raw, str) else raw
                if not isinstance(arr, list):
                    continue
                for x in arr:
                    s = str(x).strip().lower()
                    if s:
                        tags_set.add(s)
            except (TypeError, ValueError):
                continue
    return sorted(tags_set)


@bp.route('/api/tags', methods=['GET'])
@login_required
def api_tags_suggestions():
    """Distinct IOC tags for label-style autocomplete. Optional query: ?q=prefix (lowercase)."""
    q = (request.args.get('q') or '').strip().lower()
    # If admin configured an allowlist taxonomy + restriction, autocomplete is the allowlist only
    # (same as IOC submit tag UX). Otherwise distinct tags from existing IOC rows.
    try:
        (_get_setting,) = _from_app('_get_setting')
        restricted = (_get_setting('tags_restricted_enabled', 'false') or 'false').lower() == 'true'
        allowed = parse_allowed_tags_setting(_get_setting('allowed_tags', '[]'))
        if restricted and allowed:
            tags = allowed
        else:
            tags = _distinct_ioc_tags_from_db()
    except Exception:
        tags = _distinct_ioc_tags_from_db()
    if q:
        tags = [t for t in tags if t.startswith(q)]
    return jsonify({'success': True, 'tags': tags[:500]})


@bp.route('/api/tags/suggest', methods=['POST'])
@login_required
def api_tags_suggest():
    """
    Suggest one or more new tags for admin approval.
    Body: { "tag": "foo" } or { "tags": ["foo","bar"] }.
    """
    (_api_ok, _api_error, _get_setting, _set_setting, audit_log, _utcnow) = _from_app(
        '_api_ok', '_api_error', '_get_setting', '_set_setting', 'audit_log', '_utcnow'
    )
    import json
    import uuid
    try:
        if not request.is_json:
            from utils.audit_events import audit_log_event
            audit_log_event('tag_suggest_fail', 'fail', code='invalid_body', reason='JSON body required')
            return jsonify({'success': False, 'message': 'JSON body required'}), 400
        data = request.get_json(silent=True) or {}
        raw = data.get('tags')
        if raw is None:
            raw = data.get('tag')
        tags_list = normalize_tags_from_input(raw)
        if not tags_list:
            from utils.audit_events import audit_log_event
            audit_log_event('tag_suggest_fail', 'fail', code='missing_tags', reason='Missing tag(s)')
            return jsonify({'success': False, 'message': 'Missing tag(s)'}), 400

        allow_suggest = (_get_setting('tags_allow_suggest', 'true') or 'true').lower() == 'true'
        if not allow_suggest:
            from utils.audit_events import audit_log_event
            audit_log_event('tag_suggest_fail', 'fail', code='disabled', reason='Tag suggestions are disabled')
            return jsonify({'success': False, 'message': 'Tag suggestions are disabled'}), 403

        allowed = parse_allowed_tags_setting(_get_setting('allowed_tags', '[]'))
        allowed_set = set(allowed)
        # Load existing suggestions
        raw_s = (_get_setting('tag_suggestions', '[]') or '[]').strip()
        try:
            suggestions = json.loads(raw_s) if raw_s else []
        except Exception:
            suggestions = []
        if not isinstance(suggestions, list):
            suggestions = []
        pending_set = {str(x.get('tag') or '').strip().lower() for x in suggestions if isinstance(x, dict)}

        added = []
        for t in tags_list:
            tag = (t or '').strip().lower()
            if not tag:
                continue
            if tag in allowed_set:
                continue
            if tag in pending_set:
                continue
            suggestions.append({
                'id': uuid.uuid4().hex,
                'tag': tag,
                'suggested_by': current_user.username or '',
                'suggested_at': iso_utc(_utcnow()),
            })
            pending_set.add(tag)
            added.append(tag)

        _set_setting('tag_suggestions', json.dumps(suggestions, ensure_ascii=False))
        audit_log('tag_suggest', f'by={current_user.username} count={len(added)}')
        return _api_ok(data={'added': added}, message='Suggestion submitted')
    except Exception as e:
        logging.exception('api_tags_suggest failed')
        try:
            from utils.audit_events import audit_log_event
            audit_log_event('tag_suggest_fail', 'fail', code='unexpected', reason=str(e)[:200])
        except Exception:
            pass
        return _api_error(str(e), 500)


def _campaign_creator_username(campaign):
    if not getattr(campaign, 'created_by', None):
        return ''
    u = db.session.get(User, campaign.created_by)
    return (u.username if u else '') or ''


def _campaign_to_search_result_dict(campaign):
    """Single Search row for a campaign: description in comment, metadata appended."""
    creator = _campaign_creator_username(campaign)
    desc = (campaign.description or '').strip()
    meta_parts = [
        f"ID: {campaign.id}",
        f"Created by: {creator or '—'}",
        f"Direction: {getattr(campaign, 'dir', None) or 'ltr'}",
    ]
    if getattr(campaign, 'reference_image_ext', None):
        meta_parts.append('Reference image: yes')
    else:
        meta_parts.append('Reference image: no')
    meta_line = ' | '.join(meta_parts)
    comment = (desc + '\n\n' + meta_line) if desc else meta_line
    date_s = iso_utc(campaign.created_at)
    return {
        'ioc': campaign.name,
        'value': campaign.name,
        'file_type': 'Campaign',
        'date': date_s,
        'user': creator,
        'ref': f'CAMP-{campaign.id}',
        'comment': comment,
        'expiration': 'N/A',
        'line_number': campaign.id,
        'raw_line': f"Campaign:{campaign.name}",
        'expiration_status': 'Permanent',
        'expires_on': None,
        'is_expired': False,
        'status': 'Active',
        'campaign_name': None,
        'tags': [],
        'is_campaign': True,
        'campaign_id': campaign.id,
    }


def _search_matching_campaign_models(filter_type: str, query_lower: str):
    """Campaign ORM rows that should appear as standalone search results."""
    Creator = aliased(User)
    base = Campaign.query.outerjoin(Creator, Campaign.created_by == Creator.id)

    if filter_type == 'all':
        conds = [
            func.lower(Campaign.name).contains(query_lower),
            db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(query_lower)),
            db.and_(Creator.username.isnot(None), func.lower(Creator.username).contains(query_lower)),
            func.lower(cast(Campaign.created_at, String)).contains(query_lower),
        ]
        if query_lower.isdigit():
            try:
                conds.append(Campaign.id == int(query_lower))
            except ValueError:
                pass
        return base.filter(db.or_(*conds)).order_by(Campaign.created_at.desc()).limit(500).all()

    if filter_type == 'campaign':
        return base.filter(
            db.or_(
                func.lower(Campaign.name).contains(query_lower),
                db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(query_lower)),
            )
        ).order_by(Campaign.created_at.desc()).limit(500).all()

    if filter_type == 'user':
        return base.filter(
            db.and_(Creator.username.isnot(None), func.lower(Creator.username).contains(query_lower))
        ).order_by(Campaign.created_at.desc()).limit(500).all()

    if filter_type == 'comment':
        return base.filter(
            db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(query_lower))
        ).order_by(Campaign.created_at.desc()).limit(500).all()

    if filter_type == 'ioc_value':
        return base.filter(func.lower(Campaign.name).contains(query_lower)).order_by(Campaign.created_at.desc()).limit(500).all()

    if filter_type == 'file_type':
        if query_lower in ('campaign', 'קמפיין', 'camp', 'campaigns'):
            return Campaign.query.order_by(Campaign.created_at.desc()).limit(500).all()
        return []

    if filter_type == 'ticket_id':
        qn = query_lower.replace(' ', '')
        cid = None
        if qn.startswith('camp-') and len(qn) > 5 and qn[5:].isdigit():
            cid = int(qn[5:])
        elif query_lower.isdigit():
            cid = int(query_lower)
        if cid is not None:
            c = db.session.get(Campaign, cid)
            return [c] if c else []
        return []

    if filter_type == 'date':
        rows = base.filter(Campaign.created_at.isnot(None)).order_by(Campaign.created_at.desc()).limit(1000).all()
        return [
            c for c in rows
            if query_lower in (c.created_at.isoformat() if c.created_at else '').lower()
        ]

    if filter_type == 'metadata':
        return base.filter(
            db.or_(
                func.lower(Campaign.name).contains(query_lower),
                db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(query_lower)),
                db.and_(Creator.username.isnot(None), func.lower(Creator.username).contains(query_lower)),
            )
        ).order_by(Campaign.created_at.desc()).limit(500).all()

    return []


def _ioc_matches_metadata_filter(row, query_lower: str, tag_matches_fn) -> bool:
    """Metadata search: ticket, analyst, IOC submission comment, tags, campaign name/description — not IOC value."""
    if not query_lower:
        return False
    ql = query_lower
    if ql in (row.analyst or '').lower():
        return True
    if (row.ticket_id or '') and ql in (row.ticket_id or '').lower():
        return True
    if (row.comment or '') and ql in (row.comment or '').lower():
        return True
    if tag_matches_fn(getattr(row, 'tags', None), ql):
        return True
    camp = getattr(row, 'campaign', None)
    if camp is not None:
        if (camp.name or '') and ql in (camp.name or '').lower():
            return True
        if (camp.description or '') and ql in (camp.description or '').lower():
            return True
    return False


def _compute_ioc_match_hints(row, query_lower: str, filter_type: str, analyst_note_keys: set, tag_matches_fn, exp_status_fn) -> list:
    """Stable reasons for UI badges (Search & Investigate)."""
    if not query_lower:
        return []
    ft = (filter_type or 'all').strip().lower()
    ql = query_lower
    key = ((row.type or ''), (row.value or '').strip().lower())
    analyst_note_keys = analyst_note_keys or set()

    if ft == 'note':
        return ['analyst_note']
    if ft == 'comment':
        return ['ioc_comment']
    if ft == 'metadata':
        hints = []
        if ql in (row.analyst or '').lower():
            hints.append('analyst')
        if (row.ticket_id or '') and ql in (row.ticket_id or '').lower():
            hints.append('ticket')
        if (row.comment or '') and ql in (row.comment or '').lower():
            hints.append('ioc_comment')
        if tag_matches_fn(getattr(row, 'tags', None), ql):
            hints.append('tag')
        camp = getattr(row, 'campaign', None)
        if camp is not None:
            if (camp.name or '') and ql in (camp.name or '').lower():
                hints.append('campaign_name')
            if (camp.description or '') and ql in (camp.description or '').lower():
                hints.append('campaign_description')
        return hints or ['metadata']

    hints = []
    if ft in ('all', 'ioc_value') and (
        _ioc_value_text_matches_needles(row, _search_needles_from_query(query_lower))
        or ql in (row.value or '').lower()
    ):
        hints.append('ioc_value')
    if ft in ('all', 'user') and ql in (row.analyst or '').lower():
        hints.append('analyst')
    if ft in ('all', 'ticket_id') and (row.ticket_id or '') and ql in (row.ticket_id or '').lower():
        hints.append('ticket')
    if ft in ('all', 'comment') and (row.comment or '') and ql in (row.comment or '').lower():
        hints.append('ioc_comment')
    if ft in ('all', 'tag') and tag_matches_fn(getattr(row, 'tags', None), ql):
        hints.append('tag')
    camp = getattr(row, 'campaign', None)
    if ft in ('all', 'campaign') and camp is not None:
        if (camp.name or '') and ql in (camp.name or '').lower():
            hints.append('campaign_name')
        if (camp.description or '') and ql in (camp.description or '').lower():
            hints.append('campaign_description')
    if ft == 'all' and ql in (row.type or '').lower():
        hints.append('ioc_type')
    if ft in ('all', 'date') and row.created_at and ql in (row.created_at.isoformat() or '').lower():
        hints.append('created_at')
    if ft in ('all', 'expiration_status') and exp_status_fn(row, ql):
        hints.append('expiration')
    if ft == 'all' and key in analyst_note_keys:
        hints.append('analyst_note')
    return list(dict.fromkeys(hints))


def _campaign_match_hints(camp, query_lower: str, filter_type: str) -> list:
    ql = (query_lower or '').strip().lower()
    if not ql:
        return []
    ft = (filter_type or 'all').strip().lower()
    hints = []
    if (camp.name or '') and ql in (camp.name or '').lower():
        hints.append('campaign_name')
    if (camp.description or '') and ql in ((camp.description or '').lower()):
        hints.append('campaign_description')
    creator = _campaign_creator_username(camp)
    if creator and ql in creator.lower():
        hints.append('creator')
    if ft == 'date' and camp.created_at and ql in (camp.created_at.isoformat() or '').lower():
        hints.append('created_at')
    return list(dict.fromkeys(hints)) or ['campaign']


def _yara_match_hints(rule, query_lower: str, filter_type: str) -> list:
    ql = (query_lower or '').strip().lower()
    if not ql:
        return []
    ft = (filter_type or 'all').strip().lower()
    hints = []
    if ft != 'metadata' and ql in (rule.filename or '').lower():
        hints.append('yara_filename')
    if (rule.comment or '') and ql in (rule.comment or '').lower():
        hints.append('ioc_comment')
    if ql in (rule.analyst or '').lower():
        hints.append('analyst')
    if (rule.ticket_id or '') and ql in (rule.ticket_id or '').lower():
        hints.append('ticket')
    return list(dict.fromkeys(hints)) or ['yara']


def _enrich_ioc_results_with_hints(results_rows, _ioc_row_to_search_result, query_lower, filter_type, analyst_note_keys, tag_matches_fn, exp_status_fn):
    """Mutate list of dicts from IOC rows: add match_hints."""
    out = []
    for row in results_rows:
        d = _ioc_row_to_search_result(row, row.type, query_lower, filter_type)
        d['match_hints'] = _compute_ioc_match_hints(
            row, query_lower, filter_type, analyst_note_keys, tag_matches_fn, exp_status_fn
        )
        out.append(d)
    return out


def _deleted_history_match_hints(h, query_lower: str, filter_type: str) -> list:
    """Which fields matched for a deleted IOC row in Search (badges)."""
    ql = (query_lower or '').strip().lower()
    ft = (filter_type or 'all').strip().lower()
    if not ql:
        return []
    payload = {}
    if h.payload:
        try:
            payload = json.loads(h.payload)
        except (TypeError, ValueError):
            pass
    comment = (payload.get('comment') or '').lower()
    reason_l = (payload.get('reason') or '').lower()
    orig_user = (payload.get('original_analyst') or '').lower()
    value_lower = (h.ioc_value or '').lower()
    user_lower = (h.username or '').lower()
    ref = (payload.get('ticket_id') or '').lower()
    tags = payload.get('tags') or []
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except (TypeError, ValueError):
            tags = []
    tag_hit = any(ql in (str(t).lower()) for t in (tags or []))

    if ft == 'metadata':
        hints = []
        if ql in comment or ql in reason_l:
            hints.append('ioc_comment')
        if ql in user_lower or ql in orig_user:
            hints.append('analyst')
        if ql in ref:
            hints.append('ticket')
        if tag_hit:
            hints.append('tag')
        return list(dict.fromkeys(hints)) or ['metadata']

    hints = []
    if ft in ('all', 'ioc_value') and ql in value_lower:
        hints.append('ioc_value')
    if ft in ('all', 'user') and (ql in user_lower or ql in orig_user):
        hints.append('analyst')
    if ft in ('all', 'comment') and (ql in comment or ql in reason_l):
        hints.append('ioc_comment')
    if ft in ('all', 'ticket_id') and ql in ref:
        hints.append('ticket')
    if ft in ('all', 'tag') and tag_hit:
        hints.append('tag')
    if ft == 'all' and ql in (h.ioc_type or '').lower():
        hints.append('ioc_type')
    date_str = (h.at.isoformat() if h.at else '').lower()
    if ft in ('all', 'date') and ql in date_str:
        hints.append('created_at')
    return list(dict.fromkeys(hints)) or ['deleted']


def _append_campaign_search_results(results, filter_type, query_lower):
    """Append campaign rows without duplicating an existing Campaign row (same name)."""
    keys = {(r.get('file_type'), (r.get('ioc') or r.get('value') or '').lower()) for r in results}
    for camp in _search_matching_campaign_models(filter_type, query_lower):
        if camp is None:
            continue
        key = ('Campaign', (camp.name or '').lower())
        if key in keys:
            continue
        keys.add(key)
        cd = _campaign_to_search_result_dict(camp)
        cd['match_hints'] = _campaign_match_hints(camp, query_lower, filter_type)
        results.append(cd)


# ---------------------------------------------------------------------------
# IOC History
# ---------------------------------------------------------------------------

def build_ioc_history_events_list(ioc_type: str, value: str) -> list:
    """
    Build sorted lifecycle events for an IOC (type+value), same contract as GET /api/ioc-history.
    Shared with campaign graph Search mode investigate endpoint.
    """
    value_lower = (value or '').strip().lower()
    rows = (
        IocHistory.query.filter(
            IocHistory.ioc_type == ioc_type,
            func.lower(IocHistory.ioc_value) == value_lower,
        )
        .order_by(IocHistory.at.asc())
        .all()
    )
    events = []
    for r in rows:
        payload = None
        if r.payload:
            try:
                payload = json.loads(r.payload)
            except (TypeError, ValueError):
                payload = {}
        events.append({
            'event_type': r.event_type,
            'username': r.username or '',
            'at': iso_utc(r.at),
            'payload': payload or {},
        })
    has_created = any(e.get('event_type') == 'created' for e in events)
    if not has_created:
        if ioc_type == 'YARA':
            yara_created = False
            for r in rows:
                if r.event_type != 'deleted' or not r.payload:
                    continue
                try:
                    pl = json.loads(r.payload) if isinstance(r.payload, str) else {}
                except (TypeError, ValueError):
                    pl = {}
                if pl.get('original_uploaded_at'):
                    events.append({
                        'event_type': 'created',
                        'username': pl.get('original_analyst') or '',
                        'at': pl.get('original_uploaded_at'),
                        'payload': {
                            'comment': pl.get('original_comment') or '',
                            'ticket_id': pl.get('ticket_id') or '',
                        },
                    })
                    yara_created = True
                    break
            if not yara_created:
                yr = YaraRule.query.filter(func.lower(YaraRule.filename) == value_lower).first()
                if yr:
                    cname = ''
                    if yr.campaign_id:
                        camp = db.session.get(Campaign, yr.campaign_id)
                        if camp:
                            cname = camp.name or ''
                    st = (getattr(yr, 'status', None) or '') or ''
                    events.append({
                        'event_type': 'created',
                        'username': yr.analyst or '',
                        'at': iso_utc(yr.uploaded_at),
                        'payload': {
                            'comment': yr.comment or '',
                            'ticket_id': yr.ticket_id or '',
                            'campaign': cname,
                            'rule_status': st,
                        },
                    })
        else:
            ioc_row = IOC.query.filter(
                IOC.type == ioc_type,
                func.lower(IOC.value) == value_lower,
            ).first()
            if ioc_row:
                payload_hist = {}
                if ioc_row.expiration_date:
                    payload_hist['expiration_date'] = iso_utc(ioc_row.expiration_date)
                if ioc_row.comment:
                    payload_hist['comment'] = ioc_row.comment
                if ioc_row.ticket_id:
                    payload_hist['ticket_id'] = ioc_row.ticket_id
                if ioc_row.campaign_id and ioc_row.campaign:
                    payload_hist['campaign'] = ioc_row.campaign.name or ''
                if getattr(ioc_row, 'tags', None):
                    try:
                        tag_data = json.loads(ioc_row.tags) if isinstance(ioc_row.tags, str) else (ioc_row.tags or [])
                        if tag_data:
                            payload_hist['tags'] = [str(t) for t in tag_data if t]
                    except (TypeError, ValueError):
                        pass
                events.append({
                    'event_type': 'created',
                    'username': (ioc_row.analyst or '') or '',
                    'at': iso_utc(ioc_row.created_at),
                    'payload': payload_hist,
                })
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for ev in list(events):
        if ev.get('event_type') == 'created' and ev.get('payload') and ev['payload'].get('expiration_date'):
            try:
                exp_str = ev['payload']['expiration_date']
                if isinstance(exp_str, str):
                    exp_dt = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
                    if exp_dt.tzinfo:
                        exp_dt = exp_dt.replace(tzinfo=None)
                else:
                    continue
                if exp_dt < now:
                    events.append({
                        'event_type': 'expired',
                        'username': ev.get('username') or '',
                        'at': exp_str[:19] if len(exp_str) > 10 else exp_str,
                        'payload': {},
                    })
            except (ValueError, TypeError):
                pass
    events.sort(key=lambda e: (e.get('at') or ''))
    return events


@bp.route('/api/ioc-history', methods=['GET'])
@login_required
def get_ioc_history():
    """Return lifecycle events for an IOC (type+value): created, deleted. For Search & Investigate History modal."""
    ioc_type = request.args.get('type', '').strip()
    value = request.args.get('value', '').strip()
    if not ioc_type or not value:
        return jsonify({'success': False, 'message': 'Missing type or value'}), 400
    events = build_ioc_history_events_list(ioc_type, value)
    return jsonify({'success': True, 'ioc_type': ioc_type, 'ioc_value': value, 'events': events})


@bp.route('/api/stix-ioc-lookup', methods=['GET'])
@login_required
def stix_ioc_lookup():
    """
    Diagnostic: map IOC type+value to the DB row and the same STIX 2.1 Indicator dict as TAXII/feeds emit.

    Use this to verify revoke: revoked rows still appear in TAXII with ``revoked: true`` (STIX removal sync).
    Plain-text feeds (e.g. /feed/ip) omit revoked IOCs entirely.
    """
    ioc_type = request.args.get('type', '').strip()
    value = (request.args.get('value') or '').strip()
    if not ioc_type or not value:
        return jsonify({'success': False, 'message': MSG_MISSING_FIELDS_TYPE_VALUE}), 400
    if ioc_type not in IOC_FILES or ioc_type == 'YARA':
        return jsonify({'success': False, 'message': MSG_INVALID_IOC_TYPE}), 400
    if not validate_ioc(value, ioc_type):
        return jsonify({'success': False, 'message': f'Invalid {ioc_type} format'}), 400

    ioc_row_is_active = _from_app('ioc_row_is_active')[0]
    from routes.feeds import _stix_id_for_ioc, _stix_indicator_from_row

    row = IOC.query.filter(
        IOC.type == ioc_type,
        func.lower(IOC.value) == value.lower(),
    ).first()
    if not row:
        return jsonify({
            'success': True,
            'found': False,
            'ioc_type': ioc_type,
            'ioc_value': value,
            'message': 'No IOC row in the database for this type+value.',
        })

    stix_id = _stix_id_for_ioc(row)
    stix_indicator = _stix_indicator_from_row(row)
    base = (request.url_root or '').rstrip('/')
    taxii_object_path = f'/taxii2/ziochub/collections/indicators/objects/{stix_id}/'
    feed_stix_path = f'/feed/stix/{ioc_type}'

    ioc_summary = {
        'id': row.id,
        'type': row.type,
        'value': row.value,
        'revoked': bool(getattr(row, 'revoked', False)),
        'revoked_at': iso_utc(getattr(row, 'revoked_at', None)),
        'expiration_date': iso_utc(row.expiration_date),
        'modified_at': iso_utc(getattr(row, 'modified_at', None)),
        'created_at': iso_utc(row.created_at),
        'analyst': row.analyst or '',
        'is_active_for_plain_feeds': ioc_row_is_active(row),
    }

    guidance = {
        'plain_text_feeds': 'Paths like /feed/ip exclude revoked and expired IOCs — suitable for consumers that only add blocklist entries.',
        'taxii_stix_feeds': 'TAXII Get Objects and /feed/stix include revoked indicators with JSON property revoked:true so STIX-aware clients can remove blocks. If a vendor ignores revoked, it may keep blocking.',
        'outbound_push_on_revoke': 'Revoke triggers schedule_outbound_ioc_event(action=remove) for configured HTTP IOC push targets (Integrations); verify FireEye is wired there vs TAXII.',
    }

    return jsonify({
        'success': True,
        'found': True,
        'ioc': ioc_summary,
        'stix_id': stix_id,
        'stix_indicator': stix_indicator,
        'urls': {
            'taxii_get_object': base + taxii_object_path,
            'feed_stix_type': base + feed_stix_path,
        },
        'taxii_request_hint': {
            'Accept': 'application/taxii+json;version=2.1',
            'note': 'TAXII 2.1 requires this Accept header on GET object/objects.',
        },
        'guidance': guidance,
    })


# ---------------------------------------------------------------------------
# IOC Notes
# ---------------------------------------------------------------------------

@bp.route('/api/ioc-notes', methods=['GET'])
@login_required
def get_ioc_notes():
    """Return analyst notes for an IOC (type+value)."""
    ioc_type = request.args.get('type', '').strip()
    value = request.args.get('value', '').strip()
    if not ioc_type or not value:
        return jsonify({'success': False, 'message': 'Missing type or value'}), 400
    value_lower = value.lower()
    rows = (
        IocNote.query
        .filter(IocNote.ioc_type == ioc_type, func.lower(IocNote.ioc_value) == value_lower)
        .order_by(IocNote.created_at.asc())
        .all()
    )
    notes = []
    for r in rows:
        user = db.session.get(User, r.user_id)
        notes.append({
            'id': r.id,
            'username': user.username if user else '?',
            'content': r.content,
            'created_at': iso_utc(r.created_at),
        })
    return jsonify({'success': True, 'notes': notes})


@bp.route('/api/ioc-notes', methods=['POST'])
@login_required
def add_ioc_note():
    """Add an analyst note to an IOC (type+value)."""
    (
        audit_log, _log_champs_event,
        _capture_champs_before, _detect_champs_changes,
        refresh_champ_score_for_user,
    ) = _from_app(
        'audit_log', '_log_champs_event',
        '_capture_champs_before', '_detect_champs_changes',
        'refresh_champ_score_for_user',
    )
    data = request.get_json(silent=True) or {}
    ioc_type = (data.get('type') or '').strip()
    value = (data.get('value') or '').strip()
    content = (data.get('content') or '').strip()
    if not ioc_type or not value:
        return jsonify({'success': False, 'message': 'Missing IOC type or value'}), 400
    if not content:
        return jsonify({'success': False, 'message': 'Note content is required'}), 400
    if len(content) > 2000:
        return jsonify({'success': False, 'message': 'Note too long (max 2000 chars)'}), 400

    champs_before = _capture_champs_before(current_user.id, (current_user.username or '').lower())

    note = IocNote(
        ioc_type=ioc_type,
        ioc_value=value,
        user_id=current_user.id,
        content=content,
    )
    db.session.add(note)
    db.session.commit()
    # Champs Smart Effort: reward rich notes as separate effort events (1-3 pts by length)
    try:
        _log_champs_event(
            'ioc_note_add',
            user_id=current_user.id,
            payload={
                'type': ioc_type,
                'value': value[:100],
                'length': len(content),
            },
        )
    except Exception as e:
        logger.warning('Champs ioc_note_add event failed (note saved): %s', e)
    try:
        refresh_champ_score_for_user(current_user.id)
    except Exception as e:
        logger.warning('add_ioc_note: refresh_champ_score failed (note saved): %s', e)

    content_preview = (content[:150] + '...') if len(content) > 150 else content
    audit_log('IOC_NOTE_ADD', f'type={ioc_type} value={value[:80]} comment="{content_preview}"')
    response = {
        'success': True,
        'note': {
            'id': note.id,
            'username': current_user.username,
            'content': note.content,
            'created_at': iso_utc(note.created_at),
        },
    }
    try:
        response.update(_detect_champs_changes(champs_before, current_user.id, (current_user.username or '').lower()))
    except Exception as e:
        logger.warning('add_ioc_note: champs change detection failed (note saved): %s', e)
    return jsonify(response)


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def _apply_ip_country_filter(sq, country_cc):
    """Restrict query to IP IOCs whose stored GeoIP country_code matches (lowercase ISO2)."""
    if not country_cc:
        return sq
    return sq.filter(
        IOC.type == 'IP',
        IOC.country_code.isnot(None),
        func.lower(IOC.country_code) == country_cc,
    )


def _ioc_row_matches_country(row, country_cc):
    if not country_cc:
        return True
    return (
        row.type == 'IP'
        and row.country_code
        and row.country_code.lower() == country_cc
    )


def _search_browse_aggregate_counts() -> dict[str, int]:
    """Row counts for Search browse lines: ip (N), domain (N), email (N), URL, and Hash by hex length."""
    vlen = func.length(func.trim(IOC.value))

    def one(*criteria):
        q = db.session.query(func.count(IOC.id)).filter(IOC.revoked.is_(False))
        for c in criteria:
            q = q.filter(c)
        return int(q.scalar() or 0)

    yara_count = int(
        (db.session.query(func.count(YaraRule.id)).filter(YaraRule.status == 'approved').scalar() or 0)
    )
    camp_count = int((db.session.query(func.count(Campaign.id)).scalar() or 0))
    return {
        'ip': one(IOC.type == 'IP'),
        'domain': one(IOC.type == 'Domain'),
        'email': one(IOC.type == 'Email'),
        'url': one(IOC.type == 'URL'),
        'yara': yara_count,
        'campaign': camp_count,
        'hash_md5': one(IOC.type == 'Hash', vlen == 32),
        'hash_sha1': one(IOC.type == 'Hash', vlen == 40),
        'hash_sha256': one(IOC.type == 'Hash', vlen == 64),
        'hash_sha512': one(IOC.type == 'Hash', vlen == 128),
        'hash_other': one(
            IOC.type == 'Hash',
            db.or_(vlen.is_(None), ~vlen.in_((32, 40, 64, 128))),
        ),
    }


_BROWSE_AGGREGATE_KEYS = frozenset({
    'ip', 'domain', 'email', 'url', 'yara', 'campaign',
    'hash_md5', 'hash_sha1', 'hash_sha256', 'hash_sha512', 'hash_other',
})


def _ioc_query_browse_aggregate(agg: str, lifecycle: str = 'active'):
    """Return IOC query for ``browse_aggregate`` (empty ``q`` browse), or ``None`` if unknown."""
    vlen = func.length(func.trim(IOC.value))
    ag = (agg or '').strip().lower()
    q = _apply_search_lifecycle(
        IOC.query.options(joinedload(IOC.campaign)),
        lifecycle,
    )
    if ag == 'ip':
        return q.filter(IOC.type == 'IP')
    if ag == 'domain':
        return q.filter(IOC.type == 'Domain')
    if ag == 'email':
        return q.filter(IOC.type == 'Email')
    if ag == 'url':
        return q.filter(IOC.type == 'URL')
    if ag == 'yara':
        return None
    if ag == 'campaign':
        return None
    if ag == 'hash_md5':
        return q.filter(IOC.type == 'Hash', vlen == 32)
    if ag == 'hash_sha1':
        return q.filter(IOC.type == 'Hash', vlen == 40)
    if ag == 'hash_sha256':
        return q.filter(IOC.type == 'Hash', vlen == 64)
    if ag == 'hash_sha512':
        return q.filter(IOC.type == 'Hash', vlen == 128)
    if ag == 'hash_other':
        return q.filter(IOC.type == 'Hash', ~vlen.in_((32, 40, 64, 128)))
    return None


def _ioc_type_label_for_browse_aggregate(agg):
    """Map browse_aggregate bucket to ``IocHistory.ioc_type`` / ``IOC.type`` (Hash buckets → ``Hash``)."""
    if not agg:
        return None
    ag = str(agg).strip().lower()
    if ag == 'ip':
        return 'IP'
    if ag == 'domain':
        return 'Domain'
    if ag == 'email':
        return 'Email'
    if ag == 'url':
        return 'URL'
    if ag == 'yara':
        return 'YARA'
    if ag == 'campaign':
        return 'Campaign'
    if ag in ('hash_md5', 'hash_sha1', 'hash_sha256', 'hash_sha512', 'hash_other'):
        return 'Hash'
    return None


def _ioc_row_in_browse_aggregate_bucket(row, agg):
    """True if ``row`` (IOC model) belongs to the same bucket as ``_ioc_query_browse_aggregate``."""
    if not agg or row is None:
        return True
    ag = str(agg).strip().lower()
    vlen = len((getattr(row, 'value', None) or '').strip())
    if ag == 'ip':
        return row.type == 'IP'
    if ag == 'domain':
        return row.type == 'Domain'
    if ag == 'email':
        return row.type == 'Email'
    if ag == 'url':
        return row.type == 'URL'
    if ag == 'hash_md5':
        return row.type == 'Hash' and vlen == 32
    if ag == 'hash_sha1':
        return row.type == 'Hash' and vlen == 40
    if ag == 'hash_sha256':
        return row.type == 'Hash' and vlen == 64
    if ag == 'hash_sha512':
        return row.type == 'Hash' and vlen == 128
    if ag == 'hash_other':
        return row.type == 'Hash' and vlen not in (32, 40, 64, 128)
    return True


def _yara_rules_for_search_filter(filter_type, query_lower):
    """
    YARA rules are merged into Search results for unified UI. Match fields consistently with IOC
    ``filter_type`` (e.g. *user* → ``YaraRule.analyst``, not filename/comment).
    """
    ql = (query_lower or '').strip().lower()
    if not ql:
        return []
    base = YaraRule.query.filter(YaraRule.status == 'approved')
    ft = (filter_type or 'all').strip().lower()
    if ft == 'user':
        return base.filter(func.lower(YaraRule.analyst).contains(ql)).all()
    if ft == 'ioc_value':
        return base.filter(func.lower(YaraRule.filename).contains(ql)).all()
    if ft == 'ticket_id':
        return base.filter(
            YaraRule.ticket_id.isnot(None),
            func.lower(YaraRule.ticket_id).contains(ql),
        ).all()
    if ft == 'comment':
        return base.filter(
            YaraRule.comment.isnot(None),
            func.lower(YaraRule.comment).contains(ql),
        ).all()
    if ft == 'campaign':
        return (
            base.join(Campaign, YaraRule.campaign_id == Campaign.id)
            .filter(
                db.or_(
                    func.lower(Campaign.name).contains(ql),
                    db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(ql)),
                )
            )
            .all()
        )
    if ft == 'metadata':
        return base.filter(
            db.or_(
                func.lower(YaraRule.analyst).contains(ql),
                db.and_(YaraRule.ticket_id.isnot(None), func.lower(YaraRule.ticket_id).contains(ql)),
                db.and_(YaraRule.comment.isnot(None), func.lower(YaraRule.comment).contains(ql)),
            )
        ).all()
    if ft == 'all':
        return base.filter(
            db.or_(
                func.lower(YaraRule.filename).contains(ql),
                func.lower(YaraRule.comment).contains(ql),
                func.lower(YaraRule.analyst).contains(ql),
                db.and_(YaraRule.ticket_id.isnot(None), func.lower(YaraRule.ticket_id).contains(ql)),
            )
        ).all()
    if ft == 'file_type':
        if ql == 'yara':
            return base.order_by(YaraRule.uploaded_at.desc()).limit(2000).all()
        return []
    if ft in ('tag', 'note', 'date', 'expiration_status'):
        return []
    return base.filter(
        db.or_(
            func.lower(YaraRule.filename).contains(ql),
            func.lower(YaraRule.comment).contains(ql),
            func.lower(YaraRule.analyst).contains(ql),
            db.and_(YaraRule.ticket_id.isnot(None), func.lower(YaraRule.ticket_id).contains(ql)),
        )
    ).all()


def _yara_query_for_search_filter(filter_type, query_lower):
    """SQLAlchemy query for YARA search, aligned with IOC ``filter_type`` semantics."""
    ql = (query_lower or '').strip().lower()
    base = YaraRule.query.filter(YaraRule.status == 'approved')
    if not ql:
        return base
    ft = (filter_type or 'all').strip().lower()
    if ft == 'user':
        return base.filter(func.lower(YaraRule.analyst).contains(ql))
    if ft == 'ioc_value':
        return base.filter(func.lower(YaraRule.filename).contains(ql))
    if ft == 'ticket_id':
        return base.filter(YaraRule.ticket_id.isnot(None), func.lower(YaraRule.ticket_id).contains(ql))
    if ft == 'comment':
        return base.filter(YaraRule.comment.isnot(None), func.lower(YaraRule.comment).contains(ql))
    if ft == 'campaign':
        return (
            base.join(Campaign, YaraRule.campaign_id == Campaign.id)
            .filter(
                db.or_(
                    func.lower(Campaign.name).contains(ql),
                    db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(ql)),
                )
            )
        )
    if ft == 'metadata':
        return base.filter(
            db.or_(
                func.lower(YaraRule.analyst).contains(ql),
                db.and_(YaraRule.ticket_id.isnot(None), func.lower(YaraRule.ticket_id).contains(ql)),
                db.and_(YaraRule.comment.isnot(None), func.lower(YaraRule.comment).contains(ql)),
            )
        )
    if ft == 'all':
        return base.filter(
            db.or_(
                func.lower(YaraRule.filename).contains(ql),
                func.lower(YaraRule.comment).contains(ql),
                func.lower(YaraRule.analyst).contains(ql),
                db.and_(YaraRule.ticket_id.isnot(None), func.lower(YaraRule.ticket_id).contains(ql)),
            )
        )
    if ft == 'file_type':
        return base if ql == 'yara' else base.filter(YaraRule.id < 0)
    if ft in ('tag', 'note', 'date', 'expiration_status'):
        return base.filter(YaraRule.id < 0)
    return base.filter(
        db.or_(
            func.lower(YaraRule.filename).contains(ql),
            func.lower(YaraRule.comment).contains(ql),
            func.lower(YaraRule.analyst).contains(ql),
            db.and_(YaraRule.ticket_id.isnot(None), func.lower(YaraRule.ticket_id).contains(ql)),
        )
    )


@bp.route('/api/search/browse-filters', methods=['GET'])
def search_browse_filters():
    """Aggregate IOC counts for the Search browse ``<select>`` (ip (N), domain (N), email (N), md5 (N), …)."""
    try:
        return jsonify({'success': True, 'aggregates': _search_browse_aggregate_counts()})
    except Exception as e:
        logger.exception('search_browse_filters failed')
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/ip-country-codes', methods=['GET'])
def list_ip_country_codes():
    """Distinct ``country_code`` values on IP IOCs (non-empty), with row counts. Sorted by count descending."""
    try:
        code_expr = func.lower(func.trim(IOC.country_code))
        rows = (
            db.session.query(code_expr.label('code'), func.count(IOC.id).label('cnt'))
            .filter(
                IOC.type == 'IP',
                IOC.revoked.is_(False),
                IOC.country_code.isnot(None),
                func.trim(IOC.country_code) != '',
            )
            .group_by(code_expr)
            .order_by(func.count(IOC.id).desc(), code_expr.asc())
            .all()
        )
        countries = [{'code': r.code, 'count': int(r.cnt)} for r in rows if r.code and str(r.code).strip()]
        return jsonify({'success': True, 'countries': countries})
    except Exception as e:
        logger.exception('list_ip_country_codes failed')
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/search', methods=['GET'])
def search_ioc():
    """Search for an IOC across all types with optional field filter (including tag)."""
    try:
        resp = _search_ioc_impl()
        if hasattr(resp, 'get_json'):
            data = resp.get_json(silent=True)
            if isinstance(data, dict) and data.get('success') and isinstance(data.get('results'), list):
                _attach_distribution_to_results(data['results'])
                return jsonify(data), resp.status_code
        return resp
    except Exception as e:
        logger.exception('search_ioc failed')
        return jsonify({'success': False, 'message': f'Search error: {e}'}), 500


def _attach_distribution_to_results(results):
    """Add distribution[] (downstream coverage icons) to search rows (IOC and YARA)."""
    if not results:
        return results
    pairs = []
    for r in results:
        ft = (r.get('file_type') or '').strip()
        if ft == 'Campaign':
            continue
        val = (r.get('ioc') or '').strip()
        if val:
            pairs.append((ft, val))
    if not pairs:
        for r in results:
            ft = (r.get('file_type') or '').strip()
            if ft == 'Campaign':
                r['distribution'] = []
        return results
    try:
        from utils.downstream import distribution_map_for_iocs
        dmap = distribution_map_for_iocs(pairs)
        for r in results:
            ft = (r.get('file_type') or '').strip()
            if ft == 'Campaign':
                r['distribution'] = []
                continue
            key = (ft, (r.get('ioc') or '').strip())
            r['distribution'] = dmap.get(key, [])
    except Exception:
        logger.debug('attach distribution failed', exc_info=True)
    return results


def _search_ioc_impl():
    """GET /api/search implementation (see search_ioc docstring)."""
    (_tag_matches, _search_expiration_status_matches, _ioc_row_to_search_result,
     _deleted_history_matches, _history_deleted_to_search_result) = _from_app(
        '_tag_matches', '_search_expiration_status_matches', '_ioc_row_to_search_result',
        '_deleted_history_matches', '_history_deleted_to_search_result')
    query = request.args.get('q', '').strip()
    filter_type = (request.args.get('filter', 'all') or 'all').strip().lower() or 'all'
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(max(1, int(request.args.get('per_page') or request.args.get('limit') or 100)), 1000)
    country_raw = (request.args.get('country_code') or request.args.get('country') or '').strip()
    country_cc = country_raw.lower()
    if country_raw and (len(country_cc) != 2 or not country_cc.isalpha()):
        return jsonify({
            'success': False,
            'message': 'country_code must be a 2-letter ISO code (e.g. us for United States)',
        }), 400

    needles = _search_needles_from_query(query)
    narrow_browse = request.args.get('narrow_browse', '').strip().lower() in ('1', 'true', 'yes')
    # Text search should find the IOC everywhere in the DB. Browse/country filters are for empty-q
    # browsing only; they often hide legacy rows (no GeoIP country_code, wrong hash bucket, etc.).
    if query and not narrow_browse:
        country_cc = ''
        country_raw = ''

    # Allow combining free-text search with the "Browse" dropdown.
    # browse_aggregate acts as an additional type/bucket constraint (domain/email/url/hash buckets).
    browse_aggregate = (request.args.get('browse_aggregate') or '').strip().lower()
    if query and not narrow_browse:
        browse_aggregate = ''
    if browse_aggregate and browse_aggregate not in _BROWSE_AGGREGATE_KEYS:
        return jsonify({
            'success': False,
            'message': 'Invalid browse_aggregate (use ip, domain, email, url, hash_md5, hash_sha1, …)',
        }), 400

    query_lower = query.lower()
    lifecycle = _parse_search_lifecycle(request.args.get('lifecycle', 'all'))
    inactive_note = None

    # Fast path: value-shaped queries (exact / substring on IOC value).
    if query and filter_type in ('all', 'ioc_value'):
        fast_rows = _lookup_ioc_rows_by_value_for_lifecycle(query, lifecycle)
        if fast_rows:
            results = _enrich_ioc_results_with_hints(
                fast_rows[:per_page],
                _ioc_row_to_search_result,
                query_lower,
                filter_type,
                set(),
                _tag_matches,
                _search_expiration_status_matches,
            )
            _apply_revoked_terminal_status(results, fast_rows)
            out_fast = {
                'success': True,
                'query': query,
                'filter': filter_type,
                'lifecycle': lifecycle,
                'results': results,
                'count': len(results),
                'total': len(fast_rows),
                'page': page,
                'per_page': per_page,
            }
            if inactive_note:
                out_fast['search_note'] = inactive_note
            return jsonify(out_fast)
        legacy_hits = _search_legacy_main_txt_for_value(query)
        if legacy_hits:
            inactive_note = (
                'Found only in legacy data/Main/*.txt (not in SQLite). '
                'Plain feeds use the database; an old cached /feed/* response may still show this value.'
            )
            return jsonify({
                'success': True,
                'query': query,
                'filter': filter_type,
                'results': legacy_hits[:per_page],
                'count': min(len(legacy_hits), per_page),
                'total': len(legacy_hits),
                'page': page,
                'per_page': per_page,
                'search_note': inactive_note,
            })

    # Empty query: only "All columns" lists every IOC (paginated). Other filters need dedicated logic.
    if not query and not country_cc and not browse_aggregate and filter_type == 'all':
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        list_q = _apply_search_lifecycle(
            IOC.query.options(joinedload(IOC.campaign)),
            lifecycle,
            now,
        )
        total = list_q.count()
        rows = (
            list_q.order_by(IOC.created_at.desc(), IOC.id.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        results = [_ioc_row_to_search_result(row, row.type, '', 'all') for row in rows]
        return jsonify({
            'success': True,
            'query': query,
            'filter': filter_type,
            'lifecycle': lifecycle,
            'results': results,
            'count': len(results),
            'total': total,
            'page': page,
            'per_page': per_page,
        })

    # YARA-only browse bucket: behaves like other browse filters, but queries `yara_rules` instead of IOC table.
    if browse_aggregate == 'yara':
        yq = _yara_query_for_search_filter(filter_type, query.lower() if query else '')
        total = yq.count()
        rules = (
            yq.order_by(YaraRule.uploaded_at.desc(), YaraRule.id.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        results = []
        for rule in rules:
            campaign_name = None
            if rule.campaign_id:
                c = db.session.get(Campaign, rule.campaign_id)
                if c:
                    campaign_name = c.name
            results.append({
                'ioc': rule.filename,
                'value': rule.filename,
                'file_type': 'YARA',
                'date': iso_utc(rule.uploaded_at),
                'user': rule.analyst or '',
                'ref': rule.ticket_id or '',
                'comment': rule.comment or '',
                'expiration': 'NEVER',
                'line_number': rule.id,
                'raw_line': f"YARA:{rule.filename}",
                'expiration_status': 'Permanent',
                'expires_on': None,
                'is_expired': False,
                'status': 'Active',
                'campaign_name': campaign_name,
                'match_hints': _yara_match_hints(rule, query.lower() if query else '', filter_type),
            })
        return jsonify({
            'success': True,
            'query': query,
            'filter': filter_type,
            'browse_aggregate': browse_aggregate,
            'results': results,
            'count': len(results),
            'total': total,
            'page': page,
            'per_page': per_page,
        })

    # Campaign-only browse bucket.
    if browse_aggregate == 'campaign':
        if query:
            camps = _search_matching_campaign_models(filter_type, query.lower())
            total = len(camps)
            # Simple pagination over in-memory results (bounded to 500 by helper).
            start = (page - 1) * per_page
            sub = camps[start:start + per_page]
        else:
            total = Campaign.query.count()
            sub = (
                Campaign.query.order_by(Campaign.created_at.desc(), Campaign.id.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )
        results = [_campaign_to_search_result_dict(c) for c in sub]
        return jsonify({
            'success': True,
            'query': query,
            'filter': filter_type,
            'browse_aggregate': browse_aggregate,
            'results': results,
            'count': len(results),
            'total': total,
            'page': page,
            'per_page': per_page,
        })

    if not query and browse_aggregate and filter_type == 'all':
        oq = _ioc_query_browse_aggregate(browse_aggregate, lifecycle)
        if oq is None:
            return jsonify({'success': False, 'message': 'Invalid browse_aggregate'}), 400
        total = oq.count()
        rows = (
            oq.order_by(IOC.created_at.desc(), IOC.id.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        results = [_ioc_row_to_search_result(row, row.type, '', filter_type) for row in rows]
        return jsonify({
            'success': True,
            'query': query,
            'filter': filter_type,
            'lifecycle': lifecycle,
            'browse_aggregate': browse_aggregate,
            'results': results,
            'count': len(results),
            'total': total,
            'page': page,
            'per_page': per_page,
        })

    if not query and country_cc and filter_type == 'all':
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        q = _apply_search_lifecycle(
            IOC.query.options(joinedload(IOC.campaign)),
            lifecycle,
            now,
        )
        q = _apply_ip_country_filter(q, country_cc)
        total = q.count()
        rows = q.offset((page - 1) * per_page).limit(per_page).all()
        query_lower = ''
        results = [_ioc_row_to_search_result(row, row.type, query_lower, filter_type) for row in rows]
        return jsonify({
            'success': True,
            'query': query,
            'filter': filter_type,
            'lifecycle': lifecycle,
            'country_code': country_cc,
            'results': results,
            'count': len(results),
            'total': total,
            'page': page,
            'per_page': per_page,
        })

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    q = _apply_search_lifecycle(IOC.query.options(joinedload(IOC.campaign)), lifecycle, now)
    if country_cc:
        q = _apply_ip_country_filter(q, country_cc)
    if browse_aggregate:
        vlen = func.length(func.trim(IOC.value))
        ag = browse_aggregate
        if ag == 'ip':
            q = q.filter(IOC.type == 'IP')
        elif ag == 'domain':
            q = q.filter(IOC.type == 'Domain')
        elif ag == 'email':
            q = q.filter(IOC.type == 'Email')
        elif ag == 'url':
            q = q.filter(IOC.type == 'URL')
        elif ag == 'hash_md5':
            q = q.filter(IOC.type == 'Hash', vlen == 32)
        elif ag == 'hash_sha1':
            q = q.filter(IOC.type == 'Hash', vlen == 40)
        elif ag == 'hash_sha256':
            q = q.filter(IOC.type == 'Hash', vlen == 64)
        elif ag == 'hash_sha512':
            q = q.filter(IOC.type == 'Hash', vlen == 128)
        elif ag == 'hash_other':
            q = q.filter(IOC.type == 'Hash', ~vlen.in_((32, 40, 64, 128)))
    if filter_type == 'ioc_value':
        if needles:
            q = q.filter(_sql_value_matches_needles(IOC.value, needles))
        else:
            q = q.filter(func.lower(IOC.value).contains(query_lower))
    elif filter_type == 'ticket_id':
        q = q.filter(IOC.ticket_id.isnot(None), func.lower(IOC.ticket_id).contains(query_lower))
    elif filter_type == 'user':
        q = q.filter(func.lower(IOC.analyst).contains(query_lower))
    elif filter_type == 'comment':
        q = q.filter(IOC.comment.isnot(None), func.lower(IOC.comment).contains(query_lower))
    elif filter_type == 'metadata':
        q = q.outerjoin(IOC.campaign).filter(
            db.or_(
                func.lower(IOC.analyst).contains(query_lower),
                db.and_(IOC.ticket_id.isnot(None), func.lower(IOC.ticket_id).contains(query_lower)),
                db.and_(IOC.comment.isnot(None), func.lower(IOC.comment).contains(query_lower)),
                db.and_(Campaign.name.isnot(None), func.lower(Campaign.name).contains(query_lower)),
                db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(query_lower)),
                db.and_(IOC.tags.isnot(None), IOC.tags.contains(query_lower)),
            )
        )
    elif filter_type == 'campaign':
        q = q.join(IOC.campaign).filter(
            db.or_(
                func.lower(Campaign.name).contains(query_lower),
                db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(query_lower)),
            )
        )
    elif filter_type == 'file_type':
        if query_lower == 'yara':
            q = q.filter(IOC.id < 0)
        elif query_lower.upper() in ('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL'):
            q = q.filter(IOC.type == query_lower.upper())
        else:
            q = q.filter(func.lower(IOC.type).contains(query_lower))
    elif filter_type == 'expiration_status':
        if query_lower in ('active', 'פעיל', 'actif'):
            q = q.filter(db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now))
        elif query_lower in ('expired', 'פג תוקף', 'expiré'):
            q = q.filter(IOC.expiration_date.isnot(None), IOC.expiration_date <= now)
        elif query_lower in ('permanent', 'קבוע', 'permanent'):
            q = q.filter(IOC.expiration_date.is_(None))
        else:
            q = _apply_ip_country_filter(q, country_cc)
            rows_all = q.limit(1000).all()
            rows = [r for r in rows_all if _search_expiration_status_matches(r, query_lower)]
            results = _enrich_ioc_results_with_hints(
                rows, _ioc_row_to_search_result, query_lower, filter_type, set(), _tag_matches, _search_expiration_status_matches
            )
            _eo = {
                'success': True,
                'query': query,
                'filter': filter_type,
                'results': results,
                'count': len(results),
                'total': len(results),
                'page': 1,
                'per_page': per_page,
            }
            if country_cc:
                _eo['country_code'] = country_cc
            return jsonify(_eo)
    elif filter_type == 'tag':
        q = q.filter(IOC.tags.isnot(None), IOC.tags.contains(query_lower))
        q = _apply_ip_country_filter(q, country_cc)
        rows = q.limit(1000).all()
        rows = [r for r in rows if _tag_matches(r.tags, query_lower)]
        results = _enrich_ioc_results_with_hints(
            rows, _ioc_row_to_search_result, query_lower, filter_type, set(), _tag_matches, _search_expiration_status_matches
        )
        _to = {
            'success': True,
            'query': query,
            'filter': filter_type,
            'results': results,
            'count': len(results),
            'total': len(results),
            'page': 1,
            'per_page': per_page,
        }
        if country_cc:
            _to['country_code'] = country_cc
        return jsonify(_to)
    elif filter_type == 'note':
        if not query_lower:
            # Analyst notes filter with no search text: list IOCs that have at least one note (distinct type+value).
            base_pairs = (
                db.session.query(IocNote.ioc_type, IocNote.ioc_value)
                .distinct()
                .order_by(IocNote.ioc_type.asc(), IocNote.ioc_value.asc())
            )
            total = base_pairs.count()
            pairs_page = (
                base_pairs.offset((page - 1) * per_page).limit(per_page).all()
            )
            note_analyst_keys = {
                (t, (v or '').strip().lower()) for t, v in pairs_page
            }
            rows = []
            for ioc_type, ioc_val in pairs_page:
                val_l = (ioc_val or '').strip().lower()
                row = _apply_search_lifecycle(
                    IOC.query.options(joinedload(IOC.campaign)).filter(
                        IOC.type == ioc_type,
                        func.lower(IOC.value) == val_l,
                    ),
                    lifecycle,
                    now,
                ).first()
                if not row:
                    continue
                if not _ioc_row_matches_country(row, country_cc):
                    continue
                if browse_aggregate and not _ioc_row_in_browse_aggregate_bucket(row, browse_aggregate):
                    continue
                rows.append(row)
            results = _enrich_ioc_results_with_hints(
                rows, _ioc_row_to_search_result, query_lower, filter_type,
                note_analyst_keys, _tag_matches, _search_expiration_status_matches,
            )
            _no = {
                'success': True,
                'query': query,
                'filter': filter_type,
                'results': results,
                'count': len(results),
                'total': total,
                'page': page,
                'per_page': per_page,
            }
            if country_cc:
                _no['country_code'] = country_cc
            return jsonify(_no)
        note_analyst_keys = {
            (n.ioc_type, (n.ioc_value or '').strip().lower())
            for n in IocNote.query.filter(func.lower(IocNote.content).contains(query_lower)).limit(500).all()
        }
        q = _apply_ip_country_filter(q, country_cc)
        rows = q.limit(1000).all()
        rows = [r for r in rows if (r.type, (r.value or '').strip().lower()) in note_analyst_keys]
        results = _enrich_ioc_results_with_hints(
            rows, _ioc_row_to_search_result, query_lower, filter_type, note_analyst_keys, _tag_matches, _search_expiration_status_matches
        )
        _no = {
            'success': True,
            'query': query,
            'filter': filter_type,
            'results': results,
            'count': len(results),
            'total': len(results),
            'page': 1,
            'per_page': per_page,
        }
        if country_cc:
            _no['country_code'] = country_cc
        return jsonify(_no)
    elif filter_type == 'date':
        q = q.filter(IOC.created_at.isnot(None))
        q = _apply_ip_country_filter(q, country_cc)
        rows_all = q.limit(1000).all()
        rows = [r for r in rows_all if query_lower in (r.created_at.isoformat() if r.created_at else '').lower()]
        results = _enrich_ioc_results_with_hints(
            rows, _ioc_row_to_search_result, query_lower, filter_type, set(), _tag_matches, _search_expiration_status_matches
        )
        if not country_cc:
            _append_campaign_search_results(results, filter_type, query_lower)
        out = {
            'success': True,
            'query': query,
            'filter': filter_type,
            'results': results,
            'count': len(results),
            'total': len(results),
            'page': 1,
            'per_page': per_page,
        }
        if country_cc:
            out['country_code'] = country_cc
        return jsonify(out)
    elif filter_type == 'all':
        value_match_sql = _sql_value_matches_needles(IOC.value, needles) if needles else func.lower(IOC.value).contains(query_lower)
        all_conditions = [
            value_match_sql,
            func.lower(IOC.analyst).contains(query_lower),
            db.and_(IOC.ticket_id.isnot(None), func.lower(IOC.ticket_id).contains(query_lower)),
            db.and_(IOC.comment.isnot(None), func.lower(IOC.comment).contains(query_lower)),
            func.lower(IOC.type).contains(query_lower),
            db.and_(IOC.tags.isnot(None), IOC.tags.contains(query_lower)),
            db.and_(IOC.created_at.isnot(None), func.lower(cast(IOC.created_at, String)).contains(query_lower)),
        ]
        if query_lower in ('permanent', 'active', 'קבוע', 'פעיל', 'actif'):
            all_conditions.append(IOC.expiration_date.is_(None))
        if query_lower in ('active', 'פעיל', 'actif'):
            all_conditions.append(IOC.expiration_date > now)
        if query_lower in ('expired', 'פג תוקף', 'expiré'):
            all_conditions.append(db.and_(IOC.expiration_date.isnot(None), IOC.expiration_date <= now))
        q = q.outerjoin(IOC.campaign).filter(
            db.or_(
                db.or_(*all_conditions),
                db.and_(Campaign.name.isnot(None), func.lower(Campaign.name).contains(query_lower)),
                db.and_(Campaign.description.isnot(None), func.lower(Campaign.description).contains(query_lower)),
            )
        )
    else:
        value_conds = [_sql_value_matches_needles(IOC.value, needles)] if needles else [func.lower(IOC.value).contains(query_lower)]
        q = q.filter(
            db.or_(
                *value_conds,
                func.lower(IOC.analyst).contains(query_lower),
                func.lower(IOC.ticket_id).contains(query_lower),
                func.lower(IOC.comment).contains(query_lower)
            )
        )
    q = _apply_ip_country_filter(q, country_cc)
    if filter_type == 'metadata':
        ordered = q.order_by(IOC.created_at.desc()).limit(5000).all()
        filtered = [r for r in ordered if _ioc_matches_metadata_filter(r, query_lower, _tag_matches)]
        total = len(filtered)
        rows = filtered[(page - 1) * per_page: page * per_page]
    else:
        if filter_type in ('all', 'ioc_value') and needles:
            value_hit = _sql_value_matches_needles(IOC.value, needles)
            q = q.order_by(case((value_hit, 0), else_=1), IOC.created_at.desc(), IOC.id.desc())
        else:
            q = q.order_by(IOC.created_at.desc(), IOC.id.desc())
        total = q.count()
        fetch_limit = per_page
        if filter_type == 'all':
            fetch_limit = min(max(per_page, per_page * 5), 5000)
        rows = q.offset((page - 1) * per_page).limit(fetch_limit).all()
    if filter_type == 'all':
        seen_ids = set()
        deduped = []
        for r in rows:
            if r.id in seen_ids:
                continue
            seen_ids.add(r.id)
            if (
                _ioc_value_text_matches_needles(r, needles) or
                query_lower in (r.analyst or '').lower() or
                query_lower in (r.ticket_id or '').lower() or
                query_lower in (r.comment or '').lower() or
                (r.created_at and query_lower in (r.created_at.isoformat() or '').lower()) or
                _tag_matches(getattr(r, 'tags', None), query_lower) or
                (getattr(r, 'campaign', None) and (
                    query_lower in ((r.campaign.name or '').lower()) or
                    query_lower in ((r.campaign.description or '').lower())
                )) or
                query_lower in (r.type or '').lower() or
                _search_expiration_status_matches(r, query_lower)
            ):
                deduped.append(r)
        rows = deduped[:per_page]
    analyst_note_keys = set()
    if query_lower:
        if filter_type == 'all':
            analyst_note_keys = {
                (n.ioc_type, (n.ioc_value or '').strip().lower())
                for n in IocNote.query.filter(func.lower(IocNote.content).contains(query_lower)).all()
            }
        elif filter_type == 'note':
            analyst_note_keys = {
                (n.ioc_type, (n.ioc_value or '').strip().lower())
                for n in IocNote.query.filter(func.lower(IocNote.content).contains(query_lower)).limit(500).all()
            }
    if filter_type in ('all', 'note'):
        note_keys = analyst_note_keys
        if note_keys:
            existing_keys = {(r.type, (r.value or '').strip().lower()) for r in rows}
            missing = note_keys - existing_keys
            if missing:
                for ntype, nval in missing:
                    extra = _apply_search_lifecycle(
                        IOC.query.options(joinedload(IOC.campaign)).filter(
                            IOC.type == ntype, func.lower(IOC.value) == nval
                        ),
                        lifecycle,
                        now,
                    ).first()
                    if extra and _ioc_row_matches_country(extra, country_cc):
                        if browse_aggregate and not _ioc_row_in_browse_aggregate_bucket(extra, browse_aggregate):
                            continue
                        rows.append(extra)
    results = _enrich_ioc_results_with_hints(
        rows,
        _ioc_row_to_search_result,
        query_lower,
        filter_type,
        analyst_note_keys,
        _tag_matches,
        _search_expiration_status_matches,
    )
    _apply_revoked_terminal_status(results, rows)
    # Merge YARA + Campaign pseudo-rows only when not restricting by country or browse bucket.
    # browse_aggregate scopes to IOC buckets (domain/email/url/hash); YARA and Campaign rows are not in those buckets.
    if not country_cc and not browse_aggregate:
        yara_matches = _yara_rules_for_search_filter(filter_type, query_lower)
        for rule in yara_matches:
            campaign_name = None
            if rule.campaign_id:
                c = db.session.get(Campaign, rule.campaign_id)
                if c:
                    campaign_name = c.name
            results.append({
                'ioc': rule.filename,
                'value': rule.filename,
                'file_type': 'YARA',
                'date': iso_utc(rule.uploaded_at),
                'user': rule.analyst or '',
                'ref': rule.ticket_id or '',
                'comment': rule.comment or '',
                'expiration': 'NEVER',
                'line_number': rule.id,
                'raw_line': f"YARA:{rule.filename}",
                'expiration_status': 'Permanent',
                'expires_on': None,
                'is_expired': False,
                'status': 'Active',
                'campaign_name': campaign_name,
                'match_hints': _yara_match_hints(rule, query_lower, filter_type),
            })
    if not country_cc and not browse_aggregate:
        _append_campaign_search_results(results, filter_type, query_lower)
    current_keys = {(r.get('file_type'), (r.get('ioc') or r.get('value') or '').lower()) for r in results}
    if not country_cc and lifecycle != 'active':
        dq = IocHistory.query.filter(IocHistory.event_type == 'deleted')
        agg_hist_type = _ioc_type_label_for_browse_aggregate(browse_aggregate)
        if agg_hist_type:
            dq = dq.filter(IocHistory.ioc_type == agg_hist_type)
        if filter_type == 'file_type':
            if query_lower.upper() in ('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL'):
                dq = dq.filter(IocHistory.ioc_type == query_lower.upper())
            elif query_lower == 'yara':
                dq = dq.filter(IocHistory.ioc_type == 'YARA')
            else:
                dq = dq.filter(func.lower(IocHistory.ioc_type).contains(query_lower))
        deleted_rows = dq.order_by(IocHistory.at.desc()).all()
        for h in deleted_rows:
            key = (h.ioc_type, (h.ioc_value or '').lower())
            if key in current_keys:
                continue
            if not _deleted_history_matches(h, query_lower, filter_type):
                continue
            current_keys.add(key)
            dh = _history_deleted_to_search_result(h)
            dh['match_hints'] = _deleted_history_match_hints(h, query_lower, filter_type)
            results.append(dh)
    if not results and needles and filter_type in ('all', 'ioc_value'):
        exact_rows = _lookup_ioc_rows_by_value_for_lifecycle(query, lifecycle)
        inactive_note = None
        if exact_rows:
            results = _enrich_ioc_results_with_hints(
                exact_rows[:per_page],
                _ioc_row_to_search_result,
                query_lower,
                filter_type,
                set(),
                _tag_matches,
                _search_expiration_status_matches,
            )
            _apply_revoked_terminal_status(results, exact_rows)
            total = len(exact_rows)
        else:
            legacy_hits = _search_legacy_main_txt_for_value(query)
            if legacy_hits:
                results = legacy_hits[:per_page]
                total = len(legacy_hits)
                inactive_note = (
                    'Found only in legacy data/Main/*.txt (not in SQLite). '
                    'Feeds use the database; stale feed cache may still show old values.'
                )
    out = {
        'success': True,
        'query': query,
        'filter': filter_type,
        'lifecycle': lifecycle,
        'results': results,
        'count': len(results),
        'total': total,
        'page': page,
        'per_page': per_page,
    }
    if country_cc:
        out['country_code'] = country_cc
    if inactive_note:
        out['search_note'] = inactive_note
    return jsonify(out)


# ---------------------------------------------------------------------------
# All IOCs (paginated)
# ---------------------------------------------------------------------------

@bp.route('/api/all-iocs', methods=['GET'])
def get_all_iocs():
    """Get all IOCs for historical table with pagination (page, per_page).

    Optional ``country_code`` / ``country``: restrict to IP IOCs with that stored ISO2 country (e.g. ``us``).
    """
    (check_expiration_status, get_country_code) = _from_app('check_expiration_status', 'get_country_code')
    page = max(1, int(request.args.get('page', 1)))
    per_page_arg = request.args.get('per_page') or request.args.get('limit')
    per_page = min(max(1, int(per_page_arg or DEFAULT_PAGE_SIZE)), DEFAULT_IOC_LIMIT)
    country_raw = (request.args.get('country_code') or request.args.get('country') or '').strip()
    country_cc = country_raw.lower()
    if country_raw and (len(country_cc) != 2 or not country_cc.isalpha()):
        return jsonify({'success': False, 'message': 'country_code must be a 2-letter ISO code'}), 400
    base = IOC.query.filter(IOC.type != 'YARA', IOC.revoked.is_(False))
    base = _apply_ip_country_filter(base, country_cc)
    total = base.count()
    q = base.order_by(IOC.created_at.desc())
    rows = q.offset((page - 1) * per_page).limit(per_page).all()
    iocs = []
    for row in rows:
        exp_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
        exp_status = check_expiration_status(exp_str)
        item = {
            'ioc': row.value,
            'date': iso_utc(row.created_at),
            'user': row.analyst or '',
            'ref': row.ticket_id or '',
            'comment': row.comment or '',
            'expiration': exp_str,
            'file_type': row.type,
            'expiration_status': exp_status['status'],
            'is_expired': exp_status['is_expired']
        }
        if row.type == 'IP':
            item['country_code'] = get_country_code(row.value)
        if getattr(row, 'tags', None):
            try:
                item['tags'] = json.loads(row.tags) if isinstance(row.tags, str) else (row.tags or [])
            except (TypeError, ValueError):
                item['tags'] = []
        else:
            item['tags'] = []
        iocs.append(_maybe_strip_feed_identity(item))
    out = {
        'success': True,
        'iocs': iocs,
        'count': len(iocs),
        'total': total,
        'page': page,
        'per_page': per_page,
    }
    if country_cc:
        out['country_code'] = country_cc
    return jsonify(out)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@bp.route('/api/export', methods=['GET'])
def export_iocs():
    """Export IOCs as CSV or JSON. Query params: type, format (csv|json), active_only (1 to exclude expired), tag (filter by tag)."""
    (_tag_matches,) = _from_app('_tag_matches')
    ioc_type = (request.args.get('type') or '').strip()
    fmt = (request.args.get('format') or 'json').strip().lower()
    active_only = request.args.get('active_only', '0') == '1'
    tag_filter = (request.args.get('tag') or '').strip().lower()
    if ioc_type and ioc_type not in IOC_FILES:
        return jsonify({'success': False, 'message': 'Invalid type'}), 400
    if fmt not in ('csv', 'json'):
        return jsonify({'success': False, 'message': 'format must be csv or json'}), 400
    # Stored timestamps are UTC-naive; compare using UTC-naive "now".
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    export_limit = min(max(1, int(request.args.get('limit', 10000))), 100000)
    # Export excludes revoked IOCs (revoked are represented via history/TAXII revocation).
    q = IOC.query.filter(IOC.type != 'YARA', IOC.revoked.is_(False))
    if ioc_type:
        q = q.filter(IOC.type == ioc_type)
    if active_only:
        q = q.filter(db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now))
    if tag_filter:
        q = q.filter(IOC.tags.isnot(None), IOC.tags.contains(tag_filter))
    rows = q.order_by(IOC.created_at.desc()).limit(export_limit).all()
    if tag_filter:
        rows = [r for r in rows if _tag_matches(getattr(r, 'tags', None), tag_filter)]
    try:
        from utils.audit_events import audit_log_event
        if current_user.is_authenticated:
            audit_log_event(
                'IOC_EXPORT',
                'success',
                type=ioc_type or 'all',
                format=fmt,
                count=len(rows),
                active_only='1' if active_only else '0',
                tag=tag_filter or None,
            )
    except Exception:
        pass
    if fmt == 'json':
        out = []
        for row in rows:
            item = {'value': row.value, 'type': row.type, 'analyst': row.analyst or '', 'ticket_id': row.ticket_id or '',
                    'comment': row.comment or '', 'expiration': row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'Permanent',
                    'created_at': iso_utc(row.created_at)}
            if getattr(row, 'tags', None):
                try:
                    item['tags'] = json.loads(row.tags) if isinstance(row.tags, str) else (row.tags or [])
                except (TypeError, ValueError):
                    item['tags'] = []
            else:
                item['tags'] = []
            out.append(item)
        return jsonify({'success': True, 'iocs': out, 'count': len(out)})
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['value', 'type', 'analyst', 'ticket_id', 'comment', 'expiration', 'created_at', 'tags'])
    for row in rows:
        tags_str = ''
        if getattr(row, 'tags', None):
            try:
                tags_str = ','.join(json.loads(row.tags) if isinstance(row.tags, str) else (row.tags or []))
            except (TypeError, ValueError):
                pass
        writer.writerow([
            row.value, row.type, row.analyst or '', row.ticket_id or '', row.comment or '',
            row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'Permanent',
            iso_utc(row.created_at) or '',
            tags_str
        ])
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=ziochub_export.csv'}
    )


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------

@bp.route('/api/revoke', methods=['POST'])
@login_required
def revoke_ioc():
    """Revoke an IOC (soft-delete) so TAXII/STIX clients can sync removals."""
    (
        _commit_with_retry, _log_ioc_history, _log_champs_event, audit_log,
        _capture_champs_before, _detect_champs_changes, refresh_champ_score_for_user,
    ) = _from_app(
        '_commit_with_retry', '_log_ioc_history', '_log_champs_event', 'audit_log',
        '_capture_champs_before', '_detect_champs_changes', 'refresh_champ_score_for_user',
    )
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({'success': False, 'message': 'Invalid JSON body'}), 400
        ioc_type = (data.get('type') or '').strip()
        value = (data.get('value') or '').strip()
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': MSG_MISSING_FIELDS_TYPE_VALUE}), 400
        reason = (data.get('reason') or '').strip()
        if not reason:
            return jsonify({'success': False, 'message': 'A reason for deletion is required'}), 400
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': MSG_INVALID_IOC_TYPE}), 400
        row = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.strip().lower()).first()
        if not row:
            return jsonify({'success': False, 'message': MSG_IOC_NOT_FOUND}), 404

        # Prepare outbound removal push context before revoking DB row.
        remove_payload = {
            'ioc_type': row.type,
            'value': row.value,
            'analyst': (row.analyst or current_user.username or 'system'),
            'ticket_id': row.ticket_id,
            'comment': row.comment,
            'expiration_date': row.expiration_date,
            'campaign_id': row.campaign_id,
            'tags_json': row.tags,
            'user_id': row.user_id,
            'created_at': row.created_at,
        }

        champs_before = _capture_champs_before(current_user.id, (current_user.username or '').lower())

        was_expired = row.expiration_date is not None and row.expiration_date < datetime.now(timezone.utc).replace(tzinfo=None)
        analyst_name = (row.analyst or current_user.username if current_user.is_authenticated else None) or ''
        delete_payload = {'was_expired': was_expired, 'reason': reason}
        _log_ioc_history(ioc_type, value, 'deleted', current_user.username if current_user.is_authenticated else analyst_name, delete_payload)
        # Self-delete: same user submitted (user_id) and/or gets Champs credit (analyst)-no +1 deletion bonus
        deleter_un = (current_user.username or '').strip().lower()
        ioc_analyst_un = (row.analyst or '').strip().lower()
        skip_deletion_bonus = (
            (row.user_id is not None and row.user_id == current_user.id)
            or (bool(ioc_analyst_un) and ioc_analyst_un == deleter_un)
        )
        # Soft revoke (keep row.id stable so STIX id is stable)
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        row.revoked = True
        row.revoked_at = now_utc
        row.modified_at = now_utc
        _commit_with_retry()
        try:
            from utils.feed_cache import invalidate_feed_cache_after_ioc_change
            invalidate_feed_cache_after_ioc_change()
        except Exception:
            pass
        # Attribute deletion to the user who performed it (for Champs "Deletions" count)
        champs_payload = {
            'was_expired': was_expired,
            'value': value[:100],
            'type': ioc_type,
        }
        if skip_deletion_bonus:
            champs_payload['skip_deletion_bonus'] = True
        _log_champs_event('ioc_deletion', user_id=current_user.id, payload=champs_payload)
        audit_log('IOC_DELETE', f'type={ioc_type} value={value[:80]} reason={reason[:100]}')
        try:
            from flask import current_app
            from utils.cisco_esa import schedule_esa_remove_after_revoke
            schedule_esa_remove_after_revoke(current_app._get_current_object(), ioc_type, value)
        except Exception as esa_err:
            logger.warning('ESA dictionary schedule after revoke failed: %s', esa_err)

        # Outbound API remove (IOC push) - fire-and-forget.
        try:
            from flask import current_app
            from utils.outbound_ioc import schedule_outbound_ioc_event
            schedule_outbound_ioc_event(
                current_app._get_current_object(),
                action='remove',
                remove_reason='manual_delete',
                submission_method='manual_delete',
                **remove_payload,
            )
        except Exception as push_err:
            logger.warning('IOC push after revoke failed: %s', push_err)
        refresh_champ_score_for_user(current_user.id)
        response = {'success': True, 'message': f'{ioc_type} IOC deleted successfully', 'status': 'Deleted'}
        try:
            response.update(_detect_champs_changes(champs_before, current_user.id, (current_user.username or '').lower()))
        except Exception as champs_err:
            logger.warning('revoke_ioc: champs change detection failed (IOC revoked): %s', champs_err)
        return jsonify(response)
    except Exception as e:
        db.session.rollback()
        logger.exception('revoke_ioc failed: %s', e)
        return jsonify({'success': False, 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# Edit
# ---------------------------------------------------------------------------

@bp.route('/api/edit', methods=['POST'])
@login_required
def edit_ioc():
    """Edit an IOC's metadata (comment, expiration, and optional campaign assignment)."""
    (
        _commit_with_retry, _log_ioc_history, audit_log, _resolve_analyst_to_user,
        _capture_champs_before, _detect_champs_changes, _log_champs_event, refresh_champ_score_for_user,
        _get_setting,
    ) = _from_app(
        '_commit_with_retry', '_log_ioc_history', 'audit_log', '_resolve_analyst_to_user',
        '_capture_champs_before', '_detect_champs_changes', '_log_champs_event', 'refresh_champ_score_for_user',
        '_get_setting',
    )
    try:
        data = request.get_json()
        ioc_type = data.get('type', '').strip()
        value = data.get('value', '').strip()
        new_comment = data.get('comment', '')
        new_expiration = data.get('expiration', '').strip()
        campaign_name_raw = data.get('campaign_name')
        campaign_name = (campaign_name_raw.strip() if isinstance(campaign_name_raw, str) else '') or None
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': MSG_MISSING_FIELDS_TYPE_VALUE}), 400
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': MSG_INVALID_IOC_TYPE}), 400
        if new_expiration.lower() == 'permanent':
            exp_dt = None
        elif new_expiration:
            try:
                exp_dt = datetime.strptime(new_expiration, '%Y-%m-%d')
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid expiration date format. Use YYYY-MM-DD or "Permanent"'}), 400
        else:
            return jsonify({'success': False, 'message': 'Expiration is required'}), 400
        row = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.strip().lower()).first()
        if not row:
            return jsonify({'success': False, 'message': MSG_IOC_NOT_FOUND}), 404

        champs_before = _capture_champs_before(current_user.id, (current_user.username or '').lower())

        old_comment = (row.comment or '').strip()
        old_exp = 'Permanent' if row.expiration_date is None else (row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else '')
        old_ticket = (row.ticket_id or '').strip()
        old_campaign = ''
        if row.campaign_id:
            c = Campaign.query.get(row.campaign_id)
            old_campaign = (c.name if c else '').strip()
        # If IOC was expired and now becomes active again, re-push to outbound systems.
        try:
            now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
            old_was_expired = (row.expiration_date is not None) and (row.expiration_date <= now_utc)
        except Exception:
            old_was_expired = False
        try:
            old_tags_list = json.loads(row.tags) if row.tags else []
        except (TypeError, ValueError):
            old_tags_list = []
        old_tags = ', '.join(str(t) for t in old_tags_list) if old_tags_list else ''
        old_analyst = (row.analyst or '').strip()

        row.comment = sanitize_comment(new_comment) or None
        row.expiration_date = exp_dt
        new_ticket_id = data.get('ticket_id')
        if new_ticket_id is not None:
            row.ticket_id = new_ticket_id.strip() or None
        if campaign_name is None or campaign_name == '' or campaign_name.lower() == 'none':
            row.campaign_id = None
        else:
            camp = Campaign.query.filter_by(name=campaign_name).first()
            if camp:
                row.campaign_id = camp.id
            else:
                return jsonify({'success': False, 'message': f'Campaign "{campaign_name}" not found'}), 400
        if 'tags' in data:
            tags_list = normalize_tags_from_input(data.get('tags'))
            try:
                restricted = (_get_setting('tags_restricted_enabled', 'false') or 'false').lower() == 'true'
                allowed = parse_allowed_tags_setting(_get_setting('allowed_tags', '[]'))
                allow_suggest = (_get_setting('tags_allow_suggest', 'true') or 'true').lower() == 'true'
                if restricted and allowed:
                    _, invalid = enforce_allowed_tags(tags_list or [], allowed)
                    if invalid:
                        invalid = sorted(set(invalid))
                        return jsonify({
                            'success': False,
                            'message': 'Invalid tag(s). Please select from the allowed tags list.',
                            'invalid_tags': invalid,
                            'suggest_allowed': bool(allow_suggest),
                        }), 400
            except Exception:
                pass
            row.tags = json.dumps(tags_list) if tags_list else '[]'
        if row.campaign_id:
            from routes.ioc import _validate_tags_or_reject

            merged_json = merge_campaign_tags_into_tags_json(row.tags, row.campaign_id)
            merged_list = parse_tags_field(merged_json)
            valid, err = _validate_tags_or_reject(merged_list, _get_setting)
            if err is not None:
                body, code = err
                return body, code
            row.tags = json.dumps(valid) if valid else '[]'
        tags_list = parse_tags_field(row.tags)
        assign_to = data.get('user_id') or data.get('analyst')
        if assign_to is not None and str(assign_to).strip() != '':
            resolved = _resolve_analyst_to_user(assign_to)
            if resolved:
                row.user_id = resolved[0]
                row.analyst = resolved[1]
            else:
                row.user_id = current_user.id
                row.analyst = current_user.username.lower()
        new_comment_val = (row.comment or '').strip()
        new_exp_val = 'Permanent' if row.expiration_date is None else (row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else '')
        new_ticket_val = (row.ticket_id or '').strip()
        new_campaign_val = (campaign_name or '').strip() if campaign_name else ''
        new_tags_val = ', '.join(tags_list) if tags_list else ''
        new_analyst_val = (row.analyst or '').strip()

        edit_changes = []
        if old_comment != new_comment_val:
            edit_changes.append({'field': 'comment', 'old': old_comment or '\u2014', 'new': new_comment_val or '\u2014'})
        if old_exp != new_exp_val:
            edit_changes.append({'field': 'expiration', 'old': old_exp or '\u2014', 'new': new_exp_val or '\u2014'})
        if old_ticket != new_ticket_val:
            edit_changes.append({'field': 'ticket_id', 'old': old_ticket or '\u2014', 'new': new_ticket_val or '\u2014'})
        if old_campaign != new_campaign_val:
            edit_changes.append({'field': 'campaign', 'old': old_campaign or '\u2014', 'new': new_campaign_val or '\u2014'})
        if old_tags != new_tags_val:
            edit_changes.append({'field': 'tags', 'old': old_tags or '\u2014', 'new': new_tags_val or '\u2014'})
        if old_analyst != new_analyst_val:
            edit_changes.append({'field': 'analyst', 'old': old_analyst or '\u2014', 'new': new_analyst_val or '\u2014'})
        edit_payload = {'changes': edit_changes} if edit_changes else {}
        _log_ioc_history(ioc_type, value, 'edited', current_user.username, edit_payload)
        _commit_with_retry()
        changes_desc = '; '.join(f"{c['field']}: {c['old'][:30]}->{c['new'][:30]}" for c in edit_changes[:5])
        audit_log('IOC_EDIT', f'type={ioc_type} value={value[:80]} changes=[{changes_desc}]')

        # Reactivation: if previously expired, and new expiration is Permanent or future, push create again.
        try:
            now_utc2 = datetime.now(timezone.utc).replace(tzinfo=None)
            new_is_active = (row.expiration_date is None) or (row.expiration_date > now_utc2)
            if old_was_expired and new_is_active:
                from flask import current_app
                from utils.outbound_ioc import schedule_outbound_ioc_event
                schedule_outbound_ioc_event(
                    current_app._get_current_object(),
                    action='create',
                    remove_reason='',
                    ioc_type=row.type,
                    value=row.value,
                    analyst=(row.analyst or current_user.username or 'system'),
                    ticket_id=row.ticket_id,
                    comment=row.comment,
                    expiration_date=row.expiration_date,
                    campaign_id=row.campaign_id,
                    tags_json=row.tags,
                    submission_method='reactivate',
                    user_id=row.user_id,
                    created_at=row.created_at,
                )
        except Exception as e:
            logger.warning('edit_ioc: reactivation push failed: %s', e)

        # If IOC was linked to a campaign, log Champs event and return achievement data for popup
        campaign_linked = (old_campaign != new_campaign_val) and bool(new_campaign_val)
        if campaign_linked and row.campaign_id:
            try:
                _log_champs_event(
                    'ioc_campaign_link',
                    user_id=current_user.id,
                    payload={
                        'ioc_id': row.id,
                        'value': value[:100],
                        'type': row.type,
                        'campaign_id': row.campaign_id,
                        'had_campaign': bool(old_campaign),
                    },
                )
            except Exception:
                pass
            try:
                refresh_champ_score_for_user(current_user.id)
            except Exception as e:
                logger.warning('edit_ioc: refresh_champ_score failed (edit saved): %s', e)

        # SMART (#8): 1 point per tag added to existing IOC
        tags_added_count = 0
        if old_tags != new_tags_val:
            old_set = {str(t).strip().lower() for t in old_tags_list if str(t).strip()}
            new_set = {str(t).strip().lower() for t in tags_list if str(t).strip()}
            tags_added_count = len(new_set - old_set)
        if tags_added_count > 0 and _get_setting('champs_scoring_method', '1') == '8':
            try:
                _log_champs_event(
                    'ioc_tag_add',
                    user_id=current_user.id,
                    payload={'added_count': tags_added_count, 'ioc_id': row.id},
                )
                refresh_champ_score_for_user(current_user.id)
            except Exception as e:
                logger.warning('edit_ioc: ioc_tag_add event failed: %s', e)

        response = {'success': True, 'message': f'{ioc_type} IOC updated successfully'}
        if campaign_linked:
            try:
                response.update(_detect_champs_changes(champs_before, current_user.id, (current_user.username or '').lower()))
            except Exception as e:
                logger.warning('edit_ioc: champs change detection failed (edit saved): %s', e)
        return jsonify(response)
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# Recent
# ---------------------------------------------------------------------------

@bp.route('/api/recent', methods=['GET'])
def get_recent():
    """Get the latest 50 items from both IOC and YaraRule tables, merged and sorted by date (newest first)."""
    (check_expiration_status, get_country_code) = _from_app('check_expiration_status', 'get_country_code')
    limit = int(request.args.get('limit', 50))
    ioc_rows = IOC.query.filter(IOC.revoked.is_(False)).order_by(IOC.created_at.desc()).limit(limit).all()
    yara_rows = YaraRule.query.filter(YaraRule.status == 'approved').order_by(YaraRule.uploaded_at.desc()).limit(limit).all()
    combined = []
    for row in ioc_rows:
        exp_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
        exp_status = check_expiration_status(exp_str)
        dt = row.created_at
        item = {
            'id': row.id,
            'type': row.type,
            'value': row.value,
            'analyst': row.analyst or '',
            'date': iso_utc(dt),
            'ioc': row.value,
            'user': row.analyst or '',
            'ref': row.ticket_id or '',
            'comment': row.comment or '',
            'expiration': exp_str,
            'file_type': row.type,
            'expiration_status': exp_status['status'],
            'is_expired': exp_status['is_expired'],
        }
        if row.type == 'IP':
            item['country_code'] = get_country_code(row.value)
        combined.append((dt, item))
    for row in yara_rows:
        dt = row.uploaded_at
        item = {
            'id': row.id,
            'type': 'YARA',
            'value': row.filename,
            'analyst': row.analyst or '',
            'date': iso_utc(dt),
            'ioc': row.filename,
            'user': row.analyst or '',
            'ref': row.ticket_id or '',
            'comment': row.comment or '',
            'expiration': 'NEVER',
            'file_type': 'YARA',
            'expiration_status': 'Permanent',
            'is_expired': False,
        }
        combined.append((dt, item))
    combined.sort(key=lambda x: x[0] if x[0] else datetime(1970, 1, 1), reverse=True)
    recent = [_maybe_strip_feed_identity(item) for _, item in combined[:limit]]
    return jsonify({'success': True, 'recent': recent, 'count': len(recent)})
