"""
Search & Investigate routes: search, IOC history/notes, edit, revoke, export, recent.
Blueprint registered with url_prefix=None so routes keep their original /api/… paths.
"""
import json
import csv
import io
import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, Response
from flask_login import current_user
from sqlalchemy import func, cast, String
from sqlalchemy.orm import joinedload

from extensions import db
from models import Campaign, IOC, IocHistory, IocNote, YaraRule, User, UserProfile, _utcnow
from utils.decorators import login_required
from utils.refanger import sanitize_comment
from utils.validation import validate_ioc
from utils.validation_messages import (
    MSG_MISSING_FIELDS_TYPE_VALUE,
    MSG_INVALID_IOC_TYPE,
    MSG_IOC_NOT_FOUND,
)
from constants import IOC_FILES, DEFAULT_PAGE_SIZE, DEFAULT_IOC_LIMIT

logger = logging.getLogger(__name__)

bp = Blueprint('search_bp', __name__)


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


# ---------------------------------------------------------------------------
# IOC History
# ---------------------------------------------------------------------------

@bp.route('/api/ioc-history', methods=['GET'])
@login_required
def get_ioc_history():
    """Return lifecycle events for an IOC (type+value): created, deleted. For Search & Investigate History modal."""
    ioc_type = request.args.get('type', '').strip()
    value = request.args.get('value', '').strip()
    if not ioc_type or not value:
        return jsonify({'success': False, 'message': 'Missing type or value'}), 400
    value_lower = value.lower()
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
            'at': r.at.isoformat() if r.at else None,
            'payload': payload or {},
        })
    has_created = any(e.get('event_type') == 'created' for e in events)
    if not has_created:
        ioc_row = IOC.query.filter(
            IOC.type == ioc_type,
            func.lower(IOC.value) == value_lower,
        ).first()
        if ioc_row:
            payload_hist = {}
            if ioc_row.expiration_date:
                payload_hist['expiration_date'] = ioc_row.expiration_date.isoformat()
            events.append({
                'event_type': 'created',
                'username': (ioc_row.analyst or '') or '',
                'at': ioc_row.created_at.isoformat() if ioc_row.created_at else None,
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
    return jsonify({'success': True, 'ioc_type': ioc_type, 'ioc_value': value, 'events': events})


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
            'created_at': r.created_at.isoformat() if r.created_at else None,
        })
    return jsonify({'success': True, 'notes': notes})


@bp.route('/api/ioc-notes', methods=['POST'])
@login_required
def add_ioc_note():
    """Add an analyst note to an IOC (type+value)."""
    (audit_log,) = _from_app('audit_log')
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
    note = IocNote(
        ioc_type=ioc_type,
        ioc_value=value,
        user_id=current_user.id,
        content=content,
    )
    db.session.add(note)
    db.session.commit()
    content_preview = (content[:150] + '...') if len(content) > 150 else content
    audit_log('IOC_NOTE_ADD', f'type={ioc_type} value={value[:80]} comment="{content_preview}"')
    return jsonify({
        'success': True,
        'note': {
            'id': note.id,
            'username': current_user.username,
            'content': note.content,
            'created_at': note.created_at.isoformat() if note.created_at else None,
        }
    })


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@bp.route('/api/search', methods=['GET'])
def search_ioc():
    """Search for an IOC across all types with optional field filter (including tag)."""
    (_tag_matches, _search_expiration_status_matches, _ioc_row_to_search_result,
     _deleted_history_matches, _history_deleted_to_search_result) = _from_app(
        '_tag_matches', '_search_expiration_status_matches', '_ioc_row_to_search_result',
        '_deleted_history_matches', '_history_deleted_to_search_result')
    query = request.args.get('q', '').strip()
    filter_type = request.args.get('filter', 'all').strip().lower()
    if not query:
        return jsonify({'success': False, 'message': 'Search query is required'}), 400
    query_lower = query.lower()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    q = IOC.query.options(joinedload(IOC.campaign))
    if filter_type == 'ioc_value':
        q = q.filter(func.lower(IOC.value).contains(query_lower))
    elif filter_type == 'ticket_id':
        q = q.filter(IOC.ticket_id.isnot(None), func.lower(IOC.ticket_id).contains(query_lower))
    elif filter_type == 'user':
        q = q.filter(func.lower(IOC.analyst).contains(query_lower))
    elif filter_type == 'comment':
        q = q.filter(IOC.comment.isnot(None), func.lower(IOC.comment).contains(query_lower))
    elif filter_type == 'campaign':
        q = q.join(IOC.campaign).filter(func.lower(Campaign.name).contains(query_lower))
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
            rows_all = q.all()
            rows = [r for r in rows_all if _search_expiration_status_matches(r, query_lower)]
            results = [_ioc_row_to_search_result(r, r.type, query_lower, filter_type) for r in rows]
            return jsonify({
                'success': True, 'query': query, 'filter': filter_type,
                'results': results, 'count': len(results)
            })
    elif filter_type == 'tag':
        q = q.filter(IOC.tags.isnot(None), IOC.tags.contains(query_lower))
        rows = q.all()
        rows = [r for r in rows if _tag_matches(r.tags, query_lower)]
        results = [_ioc_row_to_search_result(row, row.type, query_lower, filter_type) for row in rows]
        return jsonify({
            'success': True, 'query': query, 'filter': filter_type,
            'results': results, 'count': len(results)
        })
    elif filter_type == 'note':
        note_rows = IocNote.query.filter(func.lower(IocNote.content).contains(query_lower)).all()
        note_keys = {(n.ioc_type, n.ioc_value.lower()) for n in note_rows}
        rows = q.all()
        rows = [r for r in rows if (r.type, (r.value or '').lower()) in note_keys]
        results = [_ioc_row_to_search_result(row, row.type, query_lower, filter_type) for row in rows]
        return jsonify({
            'success': True, 'query': query, 'filter': filter_type,
            'results': results, 'count': len(results)
        })
    elif filter_type == 'date':
        q = q.filter(IOC.created_at.isnot(None))
        rows_all = q.all()
        rows = [r for r in rows_all if query_lower in (r.created_at.isoformat() if r.created_at else '').lower()]
        return jsonify({
            'success': True,
            'query': query,
            'filter': filter_type,
            'results': [_ioc_row_to_search_result(r, r.type, query_lower, filter_type) for r in rows],
            'count': len(rows)
        })
    elif filter_type == 'all':
        all_conditions = [
            func.lower(IOC.value).contains(query_lower),
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
                db.and_(Campaign.name.isnot(None), func.lower(Campaign.name).contains(query_lower))
            )
        )
    else:
        q = q.filter(
            db.or_(
                func.lower(IOC.value).contains(query_lower),
                func.lower(IOC.analyst).contains(query_lower),
                func.lower(IOC.ticket_id).contains(query_lower),
                func.lower(IOC.comment).contains(query_lower)
            )
        )
    rows = q.all()
    if filter_type == 'all':
        seen_ids = set()
        deduped = []
        for r in rows:
            if r.id in seen_ids:
                continue
            seen_ids.add(r.id)
            if (
                query_lower in (r.value or '').lower() or
                query_lower in (r.analyst or '').lower() or
                query_lower in (r.ticket_id or '').lower() or
                query_lower in (r.comment or '').lower() or
                (r.created_at and query_lower in (r.created_at.isoformat() or '').lower()) or
                _tag_matches(getattr(r, 'tags', None), query_lower) or
                (getattr(r, 'campaign', None) and query_lower in ((r.campaign.name or '').lower())) or
                query_lower in (r.type or '').lower() or
                _search_expiration_status_matches(r, query_lower)
            ):
                deduped.append(r)
        rows = deduped
    if filter_type in ('all', 'note'):
        note_hits = IocNote.query.filter(func.lower(IocNote.content).contains(query_lower)).all()
        note_keys = {(n.ioc_type, n.ioc_value.lower()) for n in note_hits}
        if note_keys:
            existing_keys = {(r.type, (r.value or '').lower()) for r in rows}
            missing = note_keys - existing_keys
            if missing:
                for ntype, nval in missing:
                    extra = IOC.query.options(joinedload(IOC.campaign)).filter(
                        IOC.type == ntype, func.lower(IOC.value) == nval
                    ).first()
                    if extra:
                        rows.append(extra)
    results = [_ioc_row_to_search_result(row, row.type, query_lower, filter_type) for row in rows]
    yara_matches = YaraRule.query.filter(
        YaraRule.status == 'approved',
        db.or_(
            func.lower(YaraRule.filename).contains(query_lower),
            func.lower(YaraRule.comment).contains(query_lower)
        )
    ).all()
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
            'date': rule.uploaded_at.isoformat() if rule.uploaded_at else None,
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
        })
    current_keys = {(r.get('file_type'), (r.get('ioc') or r.get('value') or '').lower()) for r in results}
    deleted_type_filter = IocHistory.ioc_type != 'YARA'
    if filter_type == 'file_type':
        if query_lower.upper() in ('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL'):
            deleted_type_filter = db.and_(deleted_type_filter, IocHistory.ioc_type == query_lower.upper())
        else:
            deleted_type_filter = db.and_(deleted_type_filter, func.lower(IocHistory.ioc_type).contains(query_lower))
    deleted_rows = IocHistory.query.filter(
        IocHistory.event_type == 'deleted',
        deleted_type_filter
    ).order_by(IocHistory.at.desc()).all()
    for h in deleted_rows:
        key = (h.ioc_type, (h.ioc_value or '').lower())
        if key in current_keys:
            continue
        if not _deleted_history_matches(h, query_lower, filter_type):
            continue
        current_keys.add(key)
        results.append(_history_deleted_to_search_result(h))
    return jsonify({
        'success': True,
        'query': query,
        'filter': filter_type,
        'results': results,
        'count': len(results)
    })


# ---------------------------------------------------------------------------
# All IOCs (paginated)
# ---------------------------------------------------------------------------

@bp.route('/api/all-iocs', methods=['GET'])
def get_all_iocs():
    """Get all IOCs for historical table with pagination (page, per_page)."""
    (check_expiration_status, get_country_code) = _from_app('check_expiration_status', 'get_country_code')
    page = max(1, int(request.args.get('page', 1)))
    per_page_arg = request.args.get('per_page') or request.args.get('limit')
    per_page = min(max(1, int(per_page_arg or DEFAULT_PAGE_SIZE)), DEFAULT_IOC_LIMIT)
    total = IOC.query.filter(IOC.type != 'YARA').count()
    q = IOC.query.filter(IOC.type != 'YARA').order_by(IOC.created_at.desc())
    rows = q.offset((page - 1) * per_page).limit(per_page).all()
    iocs = []
    for row in rows:
        exp_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
        exp_status = check_expiration_status(exp_str)
        item = {
            'ioc': row.value,
            'date': row.created_at.isoformat() if row.created_at else None,
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
        iocs.append(item)
    return jsonify({
        'success': True, 'iocs': iocs, 'count': len(iocs), 'total': total,
        'page': page, 'per_page': per_page
    })


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
    now = datetime.now()
    q = IOC.query.filter(IOC.type != 'YARA')
    if ioc_type:
        q = q.filter(IOC.type == ioc_type)
    if active_only:
        q = q.filter(db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now))
    rows = q.order_by(IOC.created_at.desc()).all()
    if tag_filter:
        rows = [r for r in rows if _tag_matches(getattr(r, 'tags', None), tag_filter)]
    if fmt == 'json':
        out = []
        for row in rows:
            item = {'value': row.value, 'type': row.type, 'analyst': row.analyst or '', 'ticket_id': row.ticket_id or '',
                    'comment': row.comment or '', 'expiration': row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'Permanent',
                    'created_at': row.created_at.isoformat() if row.created_at else None}
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
            row.created_at.isoformat() if row.created_at else '',
            tags_str
        ])
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=threatgate_export.csv'}
    )


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------

@bp.route('/api/revoke', methods=['POST'])
@login_required
def revoke_ioc():
    """Remove an IOC from the database."""
    (_commit_with_retry, _log_ioc_history, _log_champs_event, audit_log) = _from_app(
        '_commit_with_retry', '_log_ioc_history', '_log_champs_event', 'audit_log')
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
        was_expired = row.expiration_date is not None and row.expiration_date < datetime.now(timezone.utc).replace(tzinfo=None)
        analyst_name = (row.analyst or current_user.username if current_user.is_authenticated else None) or ''
        delete_payload = {'was_expired': was_expired, 'reason': reason}
        _log_ioc_history(ioc_type, value, 'deleted', current_user.username if current_user.is_authenticated else analyst_name, delete_payload)
        db.session.delete(row)
        _commit_with_retry()
        # Attribute deletion to the user who performed it (for Champs "Deletions" count)
        _log_champs_event('ioc_deletion', user_id=current_user.id, payload={
            'was_expired': was_expired,
            'value': value[:100],
            'type': ioc_type,
        })
        audit_log('IOC_DELETE', f'type={ioc_type} value={value[:80]} reason={reason[:100]}')
        return jsonify({'success': True, 'message': f'{ioc_type} IOC revoked successfully'})
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
    (_commit_with_retry, _log_ioc_history, audit_log, _resolve_analyst_to_user) = _from_app(
        '_commit_with_retry', '_log_ioc_history', 'audit_log', '_resolve_analyst_to_user')
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
        old_comment = (row.comment or '').strip()
        old_exp = 'Permanent' if row.expiration_date is None else (row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else '')
        old_ticket = (row.ticket_id or '').strip()
        old_campaign = ''
        if row.campaign_id:
            c = Campaign.query.get(row.campaign_id)
            old_campaign = (c.name if c else '').strip()
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
            tags_raw = data.get('tags')
            if isinstance(tags_raw, list):
                tags_list = [str(t).strip() for t in tags_raw if str(t).strip()][:50]
            elif isinstance(tags_raw, str):
                tags_list = [t.strip() for t in tags_raw.split(',') if t.strip()][:50]
            else:
                tags_list = []
            row.tags = json.dumps(tags_list) if tags_list else '[]'
        else:
            tags_list = old_tags_list
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
        return jsonify({'success': True, 'message': f'{ioc_type} IOC updated successfully'})
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
    ioc_rows = IOC.query.order_by(IOC.created_at.desc()).limit(limit).all()
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
            'date': dt.isoformat() if dt else None,
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
            'date': dt.isoformat() if dt else None,
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
    recent = [item for _, item in combined[:limit]]
    return jsonify({'success': True, 'recent': recent, 'count': len(recent)})
