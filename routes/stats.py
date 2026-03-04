import json
import os
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from flask import Blueprint, request, jsonify
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from extensions import db
from models import Campaign, IOC, IocHistory, YaraRule, SanityExclusion, User, _utcnow
from utils.decorators import login_required
from utils.sanity_checks import get_feed_pulse_anomalies
from constants import IOC_FILES

log = logging.getLogger(__name__)

stats_bp = Blueprint('stats_bp', __name__)


# ---------------------------------------------------------------------------
# Lazy helpers from app
# ---------------------------------------------------------------------------
def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


# ---------------------------------------------------------------------------
# /api/stats/counts
# ---------------------------------------------------------------------------
@stats_bp.route('/api/stats/counts', methods=['GET'])
def get_stats_counts():
    """Lightweight: only active IOC counts per type + YARA count. Used to show Live Statistics numbers immediately."""
    stats = {'IP': 0, 'Domain': 0, 'Hash': 0, 'Email': 0, 'URL': 0}
    now = datetime.now()
    active_filter = db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    for ioc_type in stats:
        count = IOC.query.filter(IOC.type == ioc_type, active_filter).count()
        stats[ioc_type] = count
    yara_count = YaraRule.query.filter(YaraRule.status == 'approved').count()
    return jsonify({'success': True, 'stats': stats, 'yara_count': yara_count})


# ---------------------------------------------------------------------------
# /api/stats
# ---------------------------------------------------------------------------
@stats_bp.route('/api/stats', methods=['GET'])
def get_stats():
    """Active IOC count per type (non-expired). YARA rules count, weighted total, campaign stats, and Threat Intelligence aggregates (countries, TLDs, email domains) from ALL active IOCs."""
    (get_country_code,) = _from_app('get_country_code')

    stats = {'IP': 0, 'Domain': 0, 'Hash': 0, 'Email': 0, 'URL': 0}
    now = datetime.now()
    active_filter = db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    for ioc_type in stats:
        count = IOC.query.filter(IOC.type == ioc_type, active_filter).count()
        stats[ioc_type] = count
    yara_count = YaraRule.query.filter(YaraRule.status == 'approved').count()
    ioc_total = sum(stats.values())
    weighted_total = ioc_total + (yara_count * 5)

    # All campaigns with their active IOC counts (including campaigns with 0 IOCs)
    campaign_stats = {}
    rows = db.session.query(
        Campaign.name,
        func.count(IOC.id).label('cnt')
    ).outerjoin(IOC, db.and_(
        IOC.campaign_id == Campaign.id,
        active_filter
    )).group_by(Campaign.id, Campaign.name).all()
    for row in rows:
        if row.name:
            campaign_stats[row.name] = row.cnt or 0

    # Threat Intelligence aggregates from ALL active IOCs (not limited to 500)
    country_counts = {}
    for row in IOC.query.filter(IOC.type == 'IP', active_filter).all():
        cc = get_country_code(row.value)
        if cc:
            country_counts[cc] = country_counts.get(cc, 0) + 1
    tld_counts = {}
    for row in IOC.query.filter(IOC.type == 'Domain', active_filter).all():
        val = (row.value or '').strip()
        parts = val.split('.')
        if len(parts) > 1:
            tld = '.' + parts[-1].lower()
            tld_counts[tld] = tld_counts.get(tld, 0) + 1
    email_domain_counts = {}
    for row in IOC.query.filter(IOC.type == 'Email', active_filter).all():
        val = (row.value or '').strip()
        parts = val.split('@')
        if len(parts) > 1:
            domain = parts[1].lower()
            email_domain_counts[domain] = email_domain_counts.get(domain, 0) + 1

    return jsonify({
        'success': True,
        'stats': stats,
        'yara_count': yara_count,
        'weighted_total': weighted_total,
        'campaign_stats': campaign_stats,
        'country_counts': country_counts,
        'tld_counts': tld_counts,
        'email_domain_counts': email_domain_counts,
    })


# ---------------------------------------------------------------------------
# /api/sanity-exclude
# ---------------------------------------------------------------------------
@stats_bp.route('/api/sanity-exclude', methods=['POST', 'DELETE'])
@login_required
def api_sanity_exclude():
    """Add or remove sanity-check anomaly from exclusions."""
    (_commit_with_retry, audit_log, _log_ioc_history) = _from_app(
        '_commit_with_retry', 'audit_log', '_log_ioc_history',
    )

    if request.method == 'DELETE':
        # Un-exclude: remove by id
        try:
            data = request.get_json() or {}
            excl_id = data.get('id')
            if excl_id is None:
                return jsonify({'success': False, 'message': 'Missing id'}), 400
            excl = db.session.get(SanityExclusion, excl_id)
            if not excl:
                return jsonify({'success': False, 'message': 'Exclusion not found'}), 404
            unexcl_username = current_user.username if current_user.is_authenticated else 'unknown'
            unexcl_value = excl.value
            unexcl_ioc_type = excl.ioc_type or ''
            unexcl_anomaly = excl.anomaly_type or ''
            db.session.delete(excl)
            _log_ioc_history(unexcl_ioc_type, unexcl_value, 'unexcluded', unexcl_username, {'anomaly_type': unexcl_anomaly})
            _commit_with_retry()
            audit_log('sanity_unexclude', f'id={excl_id} value={unexcl_value[:50]}')
            return jsonify({'success': True, 'message': 'Exclusion removed'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500

    # POST: add exclusion
    try:
        data = request.get_json() or {}
        value = (data.get('value') or '').strip()
        ioc_type = (data.get('type') or data.get('ioc_type') or '').strip()
        anomaly_type = (data.get('anomaly_type') or '').strip()
        username = current_user.username if current_user.is_authenticated else ((data.get('username') or '').strip() or 'unknown')

        if not value or not anomaly_type:
            return jsonify({'success': False, 'message': 'Missing value or anomaly_type'}), 400
        if ioc_type not in IOC_FILES:
            ioc_type = ioc_type or 'unknown'

        existing = SanityExclusion.query.filter_by(
            value=value, ioc_type=ioc_type, anomaly_type=anomaly_type
        ).first()
        if existing:
            return jsonify({'success': True, 'message': 'Already excluded'})

        excl = SanityExclusion(value=value, ioc_type=ioc_type, anomaly_type=anomaly_type, excluded_by=username)
        db.session.add(excl)
        _log_ioc_history(ioc_type, value, 'excluded', username, {'anomaly_type': anomaly_type})
        _commit_with_retry()
        audit_log('sanity_exclude', f'value={value[:80]} type={ioc_type} anomaly={anomaly_type} by={username}')
        return jsonify({'success': True, 'message': 'Anomaly excluded'})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': True, 'message': 'Already excluded'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# ---------------------------------------------------------------------------
# /api/feed-pulse
# ---------------------------------------------------------------------------
@stats_bp.route('/api/feed-pulse', methods=['GET'])
def api_feed_pulse():
    """Feed Pulse: diff view of incoming (new) vs outgoing (expired) IOCs in a time window."""
    (check_allowlist,) = _from_app('check_allowlist')

    hours = min(max(1, int(request.args.get('hours', 24))), 168)  # 1-168 hours
    ioc_type = (request.args.get('type') or 'all').strip()
    if ioc_type != 'all' and ioc_type not in IOC_FILES:
        return jsonify({'success': False, 'message': 'Invalid type'}), 400

    now = datetime.now()
    cutoff = now - timedelta(hours=hours)

    type_filter = IOC.type != 'YARA'
    if ioc_type != 'all':
        type_filter = db.and_(type_filter, IOC.type == ioc_type)

    # Incoming: created in last X hours, still active
    incoming_q = IOC.query.filter(type_filter).filter(
        IOC.created_at >= cutoff,
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    )
    incoming_rows = incoming_q.order_by(IOC.created_at.desc()).all()

    # Outgoing: expired in last X hours (expiration_date between cutoff and now)
    outgoing_q = IOC.query.filter(type_filter).filter(
        IOC.expiration_date.isnot(None),
        IOC.expiration_date >= cutoff,
        IOC.expiration_date <= now
    )
    outgoing_rows = outgoing_q.order_by(IOC.expiration_date.desc()).all()

    # Deleted: IOCs deleted in last X hours (from ioc_history table)
    # Exclude YARA rules (same as incoming/outgoing filters)
    deleted_history_filter = db.and_(
        IocHistory.event_type == 'deleted',
        IocHistory.ioc_type != 'YARA'
    )
    if ioc_type != 'all':
        deleted_history_filter = db.and_(deleted_history_filter, IocHistory.ioc_type == ioc_type)
    deleted_history_rows = IocHistory.query.filter(
        deleted_history_filter,
        IocHistory.at >= cutoff
    ).order_by(IocHistory.at.desc()).all()

    # Total active (filtered by type)
    total_active = IOC.query.filter(type_filter).filter(
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).count()

    # Total all IOCs ever in system (active + expired + deleted): current table count + distinct deleted that are no longer in table
    total_in_table = IOC.query.filter(type_filter).count()
    current_keys = set(
        (r.type, (r.value or '').lower())
        for r in IOC.query.filter(type_filter).with_entities(IOC.type, IOC.value).all()
    )
    deleted_distinct = IocHistory.query.filter(
        IocHistory.event_type == 'deleted',
        IocHistory.ioc_type != 'YARA'
    ).with_entities(IocHistory.ioc_type, IocHistory.ioc_value).distinct().all()
    if ioc_type != 'all':
        deleted_distinct = [(t, v) for t, v in deleted_distinct if t == ioc_type]
    deleted_not_in_table = sum(1 for (t, v) in deleted_distinct if (t, (v or '').lower()) not in current_keys)
    total_all = total_in_table + deleted_not_in_table

    def _row_to_dict(r, reason=None):
        d = {
            'value': r.value,
            'type': r.type,
            'analyst': r.analyst or '',
            'campaign': (r.campaign.name if r.campaign else '') or '',
            'ticket_id': r.ticket_id or '',
            'expiration': r.expiration_date.strftime('%Y-%m-%d') if r.expiration_date else 'Permanent',
            'created_at': r.created_at.isoformat() if r.created_at else '',
        }
        if reason:
            d['reason'] = reason
        try:
            is_allowlisted, allow_reason = check_allowlist(d.get('value') or '', d.get('type') or '')
            if is_allowlisted:
                d['is_allowlisted'] = True
                d['allowlist_reason'] = allow_reason or ''
        except Exception:
            pass
        return d

    def _history_to_dict(h):
        """Convert IocHistory 'deleted' event to dict format for outgoing list."""
        payload = {}
        if h.payload:
            try:
                payload = json.loads(h.payload)
            except (json.JSONDecodeError, TypeError):
                pass
        expiration_str = payload.get('expiration_date', '') if payload else ''
        if expiration_str:
            try:
                exp_dt = datetime.fromisoformat(expiration_str.replace('Z', '+00:00'))
                if exp_dt.tzinfo:
                    exp_dt = exp_dt.replace(tzinfo=None)
                expiration_str = exp_dt.strftime('%Y-%m-%d')
            except (ValueError, AttributeError):
                pass
        d = {
            'value': h.ioc_value,
            'type': h.ioc_type,
            'analyst': h.username or '',
            'campaign': '',
            'ticket_id': '',
            'expiration': expiration_str or 'Permanent',
            'reason': 'Deleted',
        }
        try:
            is_allowlisted, allow_reason = check_allowlist(d.get('value') or '', d.get('type') or '')
            if is_allowlisted:
                d['is_allowlisted'] = True
                d['allowlist_reason'] = allow_reason or ''
        except Exception:
            pass
        return d

    incoming = [_row_to_dict(r) for r in incoming_rows]
    outgoing = [_row_to_dict(r, reason='Expired') for r in outgoing_rows]
    
    # Add deleted IOCs to outgoing list (avoid duplicates if IOC was expired and then deleted)
    outgoing_values_set = {(o['type'], o['value'].lower()) for o in outgoing}
    for deleted_h in deleted_history_rows:
        deleted_dict = _history_to_dict(deleted_h)
        key = (deleted_dict['type'], deleted_dict['value'].lower())
        if key not in outgoing_values_set:
            outgoing.append(deleted_dict)
            outgoing_values_set.add(key)

    # Net view: if an IOC (type, value) appears in incoming (re-added in window), do not show it in outgoing
    incoming_keys = {(d['type'], (d.get('value') or '').lower()) for d in incoming}
    outgoing = [o for o in outgoing if (o.get('type'), (o.get('value') or '').lower()) not in incoming_keys]

    # Anomaly scan: only IOCs still in the system (incoming + active). Exclude outgoing/deleted
    # so that after an IOC is deleted, its warning no longer appears in Feed Pulse.
    active_rows = IOC.query.filter(type_filter).filter(
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).limit(3000).all()
    active_list = [_row_to_dict(r) for r in active_rows]
    anomalies = get_feed_pulse_anomalies(incoming + active_list)

    # Generate allowlist anomalies for Domain/URL only (IP already covered
    # by local_ip / critical_infra anomalies). Skip if the IOC already has
    # a more specific anomaly from sanity_checks.
    existing_anomaly_keys = {f"{a.get('ioc_type','')}:{a.get('value','')}" for a in anomalies}
    allowlist_seen = set()
    try:
        for item in incoming + active_list:
            val = (item.get('value') or '').strip()
            typ = item.get('type') or ''
            if typ not in ('Domain', 'URL') or not val:
                continue
            akey = f"{typ}:{val}"
            if akey in allowlist_seen or akey in existing_anomaly_keys:
                continue
            allowlist_seen.add(akey)
            is_al, al_reason = check_allowlist(val, typ)
            if is_al:
                anomalies.append({
                    'type': 'allowlisted',
                    'value': val,
                    'message': f'Known legitimate asset — {al_reason}. Consider removing from blocklist.',
                    'ioc_type': typ,
                    'is_allowlisted': True,
                    'allowlist_reason': al_reason or '',
                })
    except Exception:
        pass

    # Filter out analyst-excluded anomalies (persisted in sanity_exclusions table)
    excl_set = set()
    try:
        for e in SanityExclusion.query.all():
            excl_set.add((e.value, e.ioc_type or '', e.anomaly_type or ''))
    except Exception:
        pass
    anomalies = [a for a in anomalies if (a.get('value', ''), a.get('ioc_type', ''), a.get('type', '')) not in excl_set]

    # Exclusions list for orange "Excluded" panel (value, type, anomaly_type, excluded_by, excluded_at, id)
    excl_list = []
    try:
        for e in SanityExclusion.query.order_by(SanityExclusion.excluded_at.desc()).limit(200).all():
            excl_list.append({
                'id': e.id,
                'value': e.value,
                'type': e.ioc_type or '',
                'anomaly_type': e.anomaly_type or '',
                'excluded_by': e.excluded_by or '',
                'excluded_at': e.excluded_at.isoformat() if e.excluded_at else '',
            })
    except Exception:
        pass

    return jsonify({
        'success': True,
        'hours': hours,
        'incoming': incoming,
        'outgoing': outgoing,
        'incoming_count': len(incoming),
        'outgoing_count': len(outgoing),
        'total_active': total_active,
        'total_all': total_all,
        'anomalies': anomalies,
        'exclusions': excl_list,
        'exclusions_count': len(excl_list),
    })
