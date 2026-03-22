"""
Reports Blueprint - provides the /api/reports/data endpoint that aggregates
all statistics for a given period (day/week/month) into a single JSON response
for the Reports tab.
"""
import json
import logging
from datetime import date, datetime, timedelta
from collections import defaultdict

from flask import Blueprint, request, jsonify, url_for
from flask_login import current_user
from sqlalchemy import func, case, and_, distinct

from extensions import db
from models import (
    IOC, IocHistory, IocNote, YaraRule, Campaign, User, UserProfile,
    SanityExclusion, ActivityEvent, ChampRankSnapshot, TeamGoal,
)
from utils.decorators import login_required
from utils.cache import get_cached, set_cached

log = logging.getLogger(__name__)

REPORTS_CACHE_TTL = 120  # seconds

reports_bp = Blueprint('reports_bp', __name__)


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


def _reports_excluded_usernames():
    """Exclude MISP sync user from Analyst Spotlight when admin chose 'Exclude from Champs'."""
    _get_setting, = _from_app('_get_setting')
    excluded = set()
    if _get_setting('misp_exclude_from_champs', 'true').lower() == 'true':
        sync_user = (_get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip()
        if sync_user:
            excluded.add(sync_user.lower())
    return excluded or None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_date(s):
    """Parse ISO date string to date object."""
    try:
        return datetime.strptime(s, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None


def _period_range(period, start_date):
    """Return (start_datetime, end_datetime) for the given period type."""
    if period == 'day':
        end = start_date
    elif period == 'week':
        end = start_date + timedelta(days=6)
    elif period == 'month':
        if start_date.month == 12:
            end = start_date.replace(year=start_date.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end = start_date.replace(month=start_date.month + 1, day=1) - timedelta(days=1)
    else:
        end = start_date + timedelta(days=6)

    start_dt = datetime.combine(start_date, datetime.min.time())
    end_dt = datetime.combine(end, datetime.max.time().replace(microsecond=0))
    return start_dt, end_dt


def _prev_period_range(period, start_date):
    """Return (prev_start_dt, prev_end_dt) for the period immediately before."""
    if period == 'day':
        prev_start = start_date - timedelta(days=1)
    elif period == 'week':
        prev_start = start_date - timedelta(days=7)
    elif period == 'month':
        prev_start = (start_date.replace(day=1) - timedelta(days=1)).replace(day=1)
    else:
        prev_start = start_date - timedelta(days=7)
    return _period_range(period, prev_start)


def _format_report_name(period, start_date, end_date):
    """Generate a human-readable report name."""
    if period == 'day':
        return f"Daily Report - {start_date.strftime('%b %d, %Y')}"
    elif period == 'week':
        return f"Weekly Report - {start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')}"
    elif period == 'month':
        return f"Monthly Report - {start_date.strftime('%B %Y')}"
    return f"Report - {start_date.strftime('%b %d')} - {end_date.strftime('%b %d, %Y')}"


def _count_in_range(model, date_col, start_dt, end_dt, extra_filter=None):
    q = db.session.query(func.count(model.id)).filter(date_col >= start_dt, date_col <= end_dt)
    if extra_filter is not None:
        q = q.filter(extra_filter)
    return q.scalar() or 0


# ---------------------------------------------------------------------------
# /api/reports/data
# ---------------------------------------------------------------------------
def _report_start_date(period, date_str):
    """Compute start_date from period and optional date_str. Returns (start_date, None) or (None, error_response)."""
    if not date_str:
        if period == 'week':
            today = date.today()
            return (today - timedelta(days=today.weekday()), None)
        if period == 'month':
            return (date.today().replace(day=1), None)
        return (date.today(), None)
    start_date = _parse_date(date_str)
    if not start_date:
        return (None, (jsonify({'success': False, 'message': 'Invalid date format'}), 400))
    return (start_date, None)


@reports_bp.route('/api/reports/data', methods=['GET'])
@login_required
def get_report_data():
    try:
        period = request.args.get('period', 'week')
        date_str = request.args.get('date')
        start_date, parse_err = _report_start_date(period, date_str)
        if parse_err is not None:
            return parse_err[0], parse_err[1]
        role = 'admin' if current_user.is_admin else 'user'
        cache_key = f'reports_data_{period}_{start_date.isoformat()}_{role}'
        cached = get_cached(cache_key)
        if cached is not None:
            return jsonify(cached)
        data, err = _get_report_data_impl()
        if err is not None:
            return err[0], err[1]
        set_cached(cache_key, data, ttl_seconds=REPORTS_CACHE_TTL)
        return jsonify(data)
    except Exception as e:
        log.exception('Reports API error')
        return jsonify({'success': False, 'message': str(e)}), 500


def _get_report_data_impl():
    period = request.args.get('period', 'week')
    date_str = request.args.get('date')

    if not date_str:
        if period == 'week':
            today = date.today()
            start_date = today - timedelta(days=today.weekday())
        elif period == 'month':
            start_date = date.today().replace(day=1)
        else:
            start_date = date.today()
    else:
        start_date = _parse_date(date_str)
        if not start_date:
            return (None, (jsonify({'success': False, 'message': 'Invalid date format'}), 400))

    start_dt, end_dt = _period_range(period, start_date)
    prev_start_dt, prev_end_dt = _prev_period_range(period, start_date)
    end_date = end_dt.date()

    # Executive KPIs: point-in-time at end of report period (so each report shows its date's data)
    active_iocs = _estimate_active_at(end_dt)
    active_iocs_prev = _estimate_active_at(prev_end_dt) or active_iocs

    yara_rules = db.session.query(func.count(YaraRule.id)).filter(
        YaraRule.status == 'approved',
        YaraRule.uploaded_at <= end_dt,
    ).scalar() or 0
    yara_rules_prev_q = db.session.query(func.count(YaraRule.id)).filter(
        YaraRule.status == 'approved',
        YaraRule.uploaded_at <= prev_end_dt,
    ).scalar() or 0

    cleanup_count = _count_in_range(IocHistory, IocHistory.at, start_dt, end_dt,
                                    IocHistory.event_type.in_(['deleted', 'expired']))
    cleanup_prev = _count_in_range(IocHistory, IocHistory.at, prev_start_dt, prev_end_dt,
                                   IocHistory.event_type.in_(['deleted', 'expired']))

    active_campaigns = _count_active_campaigns_at(end_dt)
    active_campaigns_prev = _count_active_campaigns_at(prev_end_dt) or active_campaigns

    # Net change
    incoming = _count_in_range(IOC, IOC.created_at, start_dt, end_dt)
    outgoing = cleanup_count
    net_change = incoming - outgoing
    incoming_prev = _count_in_range(IOC, IOC.created_at, prev_start_dt, prev_end_dt)
    outgoing_prev = cleanup_prev
    net_change_prev = incoming_prev - outgoing_prev

    # Feed health score (point-in-time at end_dt)
    from utils.sanity_checks import get_feed_pulse_anomalies
    active_at_end = db.or_(
        IOC.expiration_date.is_(None),
        IOC.expiration_date > end_dt,
    )
    active_iocs_rows = IOC.query.filter(
        IOC.created_at <= end_dt,
        active_at_end,
    ).order_by(IOC.created_at.desc()).limit(3000).all()
    active_iocs_list = [{'value': r.value or '', 'type': r.type or ''} for r in active_iocs_rows]
    anomalies_all = get_feed_pulse_anomalies(active_iocs_list)
    anomaly_ioc_values = set()
    for a in anomalies_all:
        anomaly_ioc_values.add(a.get('value', ''))
    feed_health = round(100 - (len(anomaly_ioc_values) / max(active_iocs, 1) * 100), 1)
    feed_health = max(0, min(100, feed_health))

    # Executive summary
    summary = _generate_summary(period, incoming, outgoing, net_change, active_iocs, yara_rules, cleanup_count)

    # ── Operations ────────────────────────────────────────────────
    type_dist_rows = db.session.query(
        IOC.type, func.count(IOC.id)
    ).filter(
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
    ).group_by(IOC.type).all()
    type_distribution = {r[0]: r[1] for r in type_dist_rows}
    # Ensure all IOC types appear (0 for missing)
    for t in ('IP', 'Domain', 'Hash', 'Email', 'URL', 'YARA'):
        if t not in type_distribution:
            type_distribution[t] = 0

    # Submission rate: by hour for day, by date for week/month
    if period == 'day':
        # Group by hour (0-23) for single-day report (SQLite strftime returns '00'-'23')
        hour_expr = func.strftime('%H', IOC.created_at)
        sub_rate_team = db.session.query(
            hour_expr.label('hour'),
            func.count(IOC.id).label('cnt'),
        ).filter(
            IOC.created_at >= start_dt, IOC.created_at <= end_dt,
            db.or_(IOC.analyst != 'misp_sync', IOC.analyst.is_(None)),
        ).group_by(hour_expr).all()

        sub_rate_misp = db.session.query(
            hour_expr.label('hour'),
            func.count(IOC.id).label('cnt'),
        ).filter(
            IOC.created_at >= start_dt, IOC.created_at <= end_dt,
            func.lower(IOC.analyst) == 'misp_sync',
        ).group_by(hour_expr).all()

        sub_rate_total = db.session.query(
            hour_expr.label('hour'),
            func.count(IOC.id).label('cnt'),
        ).filter(
            IOC.created_at >= start_dt, IOC.created_at <= end_dt,
        ).group_by(hour_expr).all()

        def _hour_list(rows):
            hour_map = {}
            for r in rows:
                h = r.hour
                if h is not None:
                    try:
                        hour_map[int(h)] = r.cnt
                    except (ValueError, TypeError):
                        pass
            return [{'hour': h, 'count': hour_map.get(h, 0)} for h in range(24)]

        submission_rate = {
            'granularity': 'hour',
            'team': _hour_list(sub_rate_team),
            'misp': _hour_list(sub_rate_misp),
            'total': _hour_list(sub_rate_total),
        }
    else:
        # Group by date for week/month
        sub_rate_team = db.session.query(
            func.date(IOC.created_at).label('day'),
            func.count(IOC.id).label('cnt'),
        ).filter(
            IOC.created_at >= start_dt, IOC.created_at <= end_dt,
            db.or_(IOC.analyst != 'misp_sync', IOC.analyst.is_(None)),
        ).group_by(func.date(IOC.created_at)).all()

        sub_rate_misp = db.session.query(
            func.date(IOC.created_at).label('day'),
            func.count(IOC.id).label('cnt'),
        ).filter(
            IOC.created_at >= start_dt, IOC.created_at <= end_dt,
            func.lower(IOC.analyst) == 'misp_sync',
        ).group_by(func.date(IOC.created_at)).all()

        sub_rate_total = db.session.query(
            func.date(IOC.created_at).label('day'),
            func.count(IOC.id).label('cnt'),
        ).filter(
            IOC.created_at >= start_dt, IOC.created_at <= end_dt,
        ).group_by(func.date(IOC.created_at)).all()

        submission_rate = {
            'granularity': 'day',
            'team': [{'date': str(r.day), 'count': r.cnt} for r in sub_rate_team],
            'misp': [{'date': str(r.day), 'count': r.cnt} for r in sub_rate_misp],
            'total': [{'date': str(r.day), 'count': r.cnt} for r in sub_rate_total],
        }

    # Top countries
    top_countries = db.session.query(
        IOC.country_code, func.count(IOC.id).label('cnt')
    ).filter(
        IOC.country_code.isnot(None),
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
    ).group_by(IOC.country_code).order_by(func.count(IOC.id).desc()).limit(10).all()

    # Campaigns created by analyst (in period) + IOC counts and type breakdown
    campaigns_created_by_analyst = _build_campaigns_created_section(start_dt, end_dt)

    # Top campaigns: derived from campaigns created in period, ordered by IOC count
    # (ensures consistency with Campaigns Created by Analyst when both are shown)
    top_campaigns = []
    for a in campaigns_created_by_analyst:
        for c in (a.get('campaigns') or []):
            top_campaigns.append({'name': c.get('name', ''), 'ioc_count': c.get('ioc_count', 0)})
    top_campaigns = sorted(top_campaigns, key=lambda x: -x['ioc_count'])[:10]

    # Yara per campaign
    yara_per_campaign = {}
    yc_rows = db.session.query(Campaign.name, func.count(YaraRule.id)).join(
        YaraRule, YaraRule.campaign_id == Campaign.id
    ).filter(
        YaraRule.uploaded_at >= start_dt, YaraRule.uploaded_at <= end_dt,
    ).group_by(Campaign.name).all()
    for name, cnt in yc_rows:
        yara_per_campaign[name] = cnt

    # Submission methods
    method_rows = db.session.query(
        IOC.submission_method, func.count(IOC.id)
    ).filter(
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
    ).group_by(IOC.submission_method).all()
    submission_methods = {(r[0] or 'single'): r[1] for r in method_rows}

    # Expiration policy
    permanent = IOC.query.filter(IOC.expiration_date.is_(None), IOC.created_at >= start_dt, IOC.created_at <= end_dt).count()
    with_expiry = IOC.query.filter(IOC.expiration_date.isnot(None), IOC.created_at >= start_dt, IOC.created_at <= end_dt).count()
    expired_in_period = _count_in_range(IocHistory, IocHistory.at, start_dt, end_dt,
                                        IocHistory.event_type == 'expired')
    expiration_policy = {'permanent': permanent, 'active_expiry': with_expiry, 'expired': expired_in_period}

    # Top TLDs
    top_tlds = db.session.query(
        IOC.tld, func.count(IOC.id).label('cnt')
    ).filter(
        IOC.tld.isnot(None),
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
    ).group_by(IOC.tld).order_by(func.count(IOC.id).desc()).limit(10).all()

    # IOC quality
    total_in_period = incoming
    with_comment = db.session.query(func.count(IOC.id)).filter(
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
        IOC.comment.isnot(None), IOC.comment != '',
    ).scalar() or 0
    with_ticket = db.session.query(func.count(IOC.id)).filter(
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
        IOC.ticket_id.isnot(None), IOC.ticket_id != '',
    ).scalar() or 0
    with_campaign = db.session.query(func.count(IOC.id)).filter(
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
        IOC.campaign_id.isnot(None),
    ).scalar() or 0
    with_tags = db.session.query(func.count(IOC.id)).filter(
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
        IOC.tags.isnot(None), IOC.tags != '[]', IOC.tags != '',
    ).scalar() or 0
    avg_comment_len = db.session.query(func.avg(func.length(IOC.comment))).filter(
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
        IOC.comment.isnot(None), IOC.comment != '',
    ).scalar() or 0

    ioc_quality = {
        'with_comment_pct': round(with_comment / max(total_in_period, 1) * 100, 1),
        'with_ticket_pct': round(with_ticket / max(total_in_period, 1) * 100, 1),
        'with_campaign_pct': round(with_campaign / max(total_in_period, 1) * 100, 1),
        'with_tags_pct': round(with_tags / max(total_in_period, 1) * 100, 1),
        'avg_comment_length': round(avg_comment_len, 1),
    }

    # Anomalies summary (by type) + full list for detailed display
    anomaly_types = defaultdict(int)
    anomaly_samples = defaultdict(list)  # up to 3 samples per type
    for a in anomalies_all:
        t = a.get('type', a.get('anomaly_type', 'unknown'))
        anomaly_types[t] += 1
        if len(anomaly_samples[t]) < 3:
            anomaly_samples[t].append({
                'value': (a.get('value') or '')[:60],
                'message': a.get('message', ''),
            })
    anomalies_summary = [
        {'type': t, 'count': c, 'samples': anomaly_samples.get(t, [])}
        for t, c in sorted(anomaly_types.items(), key=lambda x: -x[1])
    ]

    # YARA quality
    yara_total_approved = YaraRule.query.filter(YaraRule.status == 'approved',
                                                YaraRule.uploaded_at >= start_dt,
                                                YaraRule.uploaded_at <= end_dt).count()
    yara_pending = YaraRule.query.filter(YaraRule.status == 'pending',
                                         YaraRule.uploaded_at >= start_dt,
                                         YaraRule.uploaded_at <= end_dt).count()
    yara_avg_quality = db.session.query(func.avg(YaraRule.quality_points)).filter(
        YaraRule.uploaded_at >= start_dt, YaraRule.uploaded_at <= end_dt,
    ).scalar() or 0
    yara_with_campaign = db.session.query(func.count(YaraRule.id)).filter(
        YaraRule.campaign_id.isnot(None),
        YaraRule.uploaded_at >= start_dt, YaraRule.uploaded_at <= end_dt,
    ).scalar() or 0
    yara_with_ticket = db.session.query(func.count(YaraRule.id)).filter(
        YaraRule.ticket_id.isnot(None), YaraRule.ticket_id != '',
        YaraRule.uploaded_at >= start_dt, YaraRule.uploaded_at <= end_dt,
    ).scalar() or 0
    yara_total_in_period = yara_total_approved + yara_pending + YaraRule.query.filter(
        YaraRule.status == 'rejected',
        YaraRule.uploaded_at >= start_dt, YaraRule.uploaded_at <= end_dt,
    ).count()

    yara_quality = {
        'total_approved': yara_total_approved,
        'pending': yara_pending,
        'avg_quality': round(yara_avg_quality, 1),
        'with_campaign_pct': round(yara_with_campaign / max(yara_total_in_period, 1) * 100, 1),
        'with_ticket_pct': round(yara_with_ticket / max(yara_total_in_period, 1) * 100, 1),
    }

    # Rare finds
    rare_rows = db.session.query(
        IOC.rare_find_type, IOC.value, IOC.country_code, IOC.tld, IOC.email_domain, IOC.analyst,
    ).filter(
        IOC.rare_find_type.isnot(None),
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
    ).limit(20).all()
    rare_finds = []
    for r in rare_rows:
        detail = r.country_code or r.tld or r.email_domain or ''
        rare_finds.append({'type': r.rare_find_type, 'value': r.value, 'detail': detail, 'discoverer': r.analyst})

    # Email domains
    email_domain_rows = db.session.query(
        IOC.email_domain, func.count(IOC.id).label('cnt')
    ).filter(
        IOC.email_domain.isnot(None),
        IOC.created_at >= start_dt, IOC.created_at <= end_dt,
    ).group_by(IOC.email_domain).order_by(func.count(IOC.id).desc()).limit(10).all()

    # ── Analysts ──────────────────────────────────────────────────
    analysts_data = _build_analysts_section(start_dt, end_dt, prev_start_dt, prev_end_dt)

    # ── Mentorship Insights (Admin only) ──────────────────────────
    mentorship_insights = []
    if current_user.is_admin:
        try:
            from utils.mentorship import compute_mentorship_insights
            mentorship_insights = compute_mentorship_insights(
                start_dt, end_dt, prev_start_dt, prev_end_dt, max_findings=5
            )
        except Exception as e:
            log.error(f'Mentorship insights error: {e}')

    # ── Available periods ─────────────────────────────────────────
    available_periods = _compute_available_periods()

    data = {
        'success': True,
        'period': period,
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'report_name': _format_report_name(period, start_date, end_date),
        'executive': {
            'active_iocs': active_iocs,
            'active_iocs_prev': active_iocs_prev,
            'yara_rules': yara_rules,
            'yara_rules_prev': yara_rules_prev_q,
            'cleanup_count': cleanup_count,
            'cleanup_count_prev': cleanup_prev,
            'active_campaigns': active_campaigns,
            'active_campaigns_prev': active_campaigns_prev,
            'net_change': net_change,
            'net_change_prev': net_change_prev,
            'feed_health_score': feed_health,
            'feed_health_score_prev': feed_health,  # approx
            'summary_text': summary,
        },
        'operations': {
            'type_distribution': type_distribution,
            'submission_rate': submission_rate,
            'top_countries': [{'code': r[0], 'count': r[1]} for r in top_countries],
            'top_campaigns': [{'name': r['name'], 'ioc_count': r['ioc_count'], 'yara_count': yara_per_campaign.get(r['name'], 0)} for r in top_campaigns],
            'campaigns_created_by_analyst': campaigns_created_by_analyst,
            'submission_methods': submission_methods,
            'expiration_policy': expiration_policy,
            'top_tlds': [{'tld': r[0], 'count': r[1]} for r in top_tlds],
            'ioc_quality': ioc_quality,
            'anomalies_summary': anomalies_summary,
            'yara_quality': yara_quality,
            'rare_finds': rare_finds,
            'email_domains': [{'domain': r[0], 'count': r[1]} for r in email_domain_rows],
        },
        'analysts': {
            **analysts_data,
            'mentorship_insights': mentorship_insights,
        },
        'available_periods': available_periods,
    }
    return (data, None)


# ---------------------------------------------------------------------------
# /api/reports/periods - list available reports for the sidebar
# ---------------------------------------------------------------------------
@reports_bp.route('/api/reports/periods', methods=['GET'])
@login_required
def get_report_periods():
    period = request.args.get('period', 'week')
    periods = _compute_available_periods(period_type=period, limit=30)
    return jsonify({'success': True, 'periods': periods})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _estimate_active_at(dt):
    """Estimate active IOC count at a past datetime (approximation)."""
    created_before = IOC.query.filter(IOC.created_at <= dt).count()
    deleted_before = db.session.query(func.count(IocHistory.id)).filter(
        IocHistory.event_type.in_(['deleted', 'expired']),
        IocHistory.at <= dt,
    ).scalar() or 0
    return max(0, created_before - deleted_before)


def _count_active_campaigns_at(dt):
    """Count distinct campaigns that had at least one IOC active at datetime dt.
    Approximation: created <= dt and (expiration null or > dt). Deletions via IocHistory
    are not accounted for (would require type+value join and event ordering)."""
    active_at_dt = db.or_(
        IOC.expiration_date.is_(None),
        IOC.expiration_date > dt,
    )
    return db.session.query(func.count(distinct(IOC.campaign_id))).filter(
        IOC.campaign_id.isnot(None),
        IOC.created_at <= dt,
        active_at_dt,
    ).scalar() or 0


def _generate_summary(period, incoming, outgoing, net_change, active_iocs, yara_rules, cleanup):
    """Generate a one-line executive summary."""
    period_word = {'day': 'today', 'week': 'this week', 'month': 'this month'}.get(period, 'this period')
    direction = 'grew' if net_change >= 0 else 'decreased'
    return (
        f"During {period_word}, the team added {incoming} indicators and removed {outgoing}. "
        f"The active feed {direction} by {abs(net_change)} to {active_iocs} total IOCs "
        f"with {yara_rules} YARA rules in production. "
        f"Cleanup score: {cleanup} stale indicators removed."
    )


def _build_campaigns_created_section(start_dt, end_dt):
    """
    Build list of campaigns created in period, grouped by analyst.
    Each analyst: { analyst, display_name, campaigns: [ { name, ioc_count, ioc_types: { IP: 5, ... } } ] }
    """
    campaigns = Campaign.query.filter(
        Campaign.created_at >= start_dt,
        Campaign.created_at <= end_dt,
        Campaign.created_by.isnot(None),
    ).order_by(Campaign.created_at).all()

    users_map = {u.id: u for u in User.query.filter_by(is_active=True).all()}
    profiles = {p.user_id: p for p in UserProfile.query.all()}

    by_user = defaultdict(list)
    for c in campaigns:
        uid = c.created_by
        user = users_map.get(uid)
        username = (user.username or '').lower() if user else 'unknown'
        profile = profiles.get(uid)
        display_name = (profile.display_name if profile and profile.display_name else username) if user else 'unknown'

        # IOC count and type breakdown for this campaign
        ioc_rows = db.session.query(IOC.type, func.count(IOC.id)).filter(
            IOC.campaign_id == c.id,
        ).group_by(IOC.type).all()
        ioc_types = {t: cnt for t, cnt in ioc_rows}
        ioc_count = sum(ioc_types.values())

        by_user[(uid, username, display_name)].append({
            'name': c.name,
            'ioc_count': ioc_count,
            'ioc_types': ioc_types,
        })

    result = []
    for (uid, username, display_name), camp_list in sorted(by_user.items(), key=lambda x: (-len(x[1]), x[0][1])):
        result.append({
            'analyst': username,
            'display_name': display_name,
            'campaigns': camp_list,
        })
    return result


def _build_analysts_section(start_dt, end_dt, prev_start_dt, prev_end_dt):
    """Build the analysts section: podium, leaderboard, team goal. Respects 'Exclude from Champs' for MISP sync."""
    from utils.champs import compute_analyst_scores, _get_level_and_xp, _get_nickname, _get_badges

    _get_setting, = _from_app('_get_setting')
    scoring_method = _get_setting('champs_scoring_method', '1')
    exclude_usernames = _reports_excluded_usernames()

    users_map = {u.id: u for u in User.query.filter_by(is_active=True).all()}
    profiles = {p.user_id: p for p in UserProfile.query.all()}

    scores = compute_analyst_scores(
        db, IOC, YaraRule, User, ActivityEvent,
        start_dt=start_dt, end_dt=end_dt,
        scoring_method=scoring_method,
        exclude_usernames=exclude_usernames,
    )

    # Podium - top 3
    podium = []
    for r in scores[:3]:
        uid = r.get('user_id')
        user = users_map.get(uid)
        profile = profiles.get(uid)
        display_name = (profile.display_name if profile and profile.display_name else
                        (user.username if user else r['analyst']))
        avatar_url = url_for('static', filename=profile.avatar_path) if profile and profile.avatar_path else None

        level, xp_in, xp_to, _ = _get_level_and_xp(r['score'])

        # IOC type counts for nickname
        type_counts = {}
        if uid:
            tc_rows = db.session.query(IOC.type, func.count(IOC.id)).filter(IOC.user_id == uid).group_by(IOC.type).all()
            type_counts = {t: c for t, c in tc_rows}
        emoji, nickname = _get_nickname(type_counts)

        analyst_daily = defaultdict(int)
        badges = _get_badges(db, IOC, YaraRule, ActivityEvent, r['analyst'], uid, {}, {})

        # Activity sparkline (last 7 days)
        today = date.today()
        sparkline = []
        for i in range(6, -1, -1):
            d = today - timedelta(days=i)
            cnt = db.session.query(func.count(IOC.id)).filter(
                IOC.user_id == uid, func.date(IOC.created_at) == d
            ).scalar() if uid else 0
            sparkline.append(cnt or 0)

        podium.append({
            'rank': r['rank'],
            'username': r['analyst'],
            'display_name': display_name,
            'avatar_url': avatar_url,
            'score': r['score'],
            'total_iocs': r['total_iocs'],
            'yara_count': r['yara_count'],
            'deletion_count': r.get('deletion_count', 0),
            'streak_days': r['streak_days'],
            'level': level,
            'xp_in_level': xp_in,
            'xp_to_next': xp_to,
            'nickname': nickname,
            'nickname_emoji': emoji,
            'badges': [{'key': b} for b in badges],
            'activity_sparkline': sparkline,
        })

    # Full leaderboard
    leaderboard = []
    for r in scores:
        uid = r.get('user_id')
        profile = profiles.get(uid)
        display_name = (profile.display_name if profile and profile.display_name else r['analyst'])
        leaderboard.append({
            'rank': r['rank'],
            'analyst': r['analyst'],
            'display_name': display_name,
            'total_iocs': r['total_iocs'],
            'yara_count': r['yara_count'],
            'deletion_count': r.get('deletion_count', 0),
            'score': r['score'],
            'streak_days': r['streak_days'],
        })

    # Team goal
    team_goal = None
    active_goal = TeamGoal.query.filter_by(is_active=True).first()
    if active_goal:
        from utils.champs import compute_team_goal_current
        current_val = compute_team_goal_current(db, active_goal, IOC, YaraRule, ActivityEvent)
        team_goal = {
            'title': active_goal.title,
            'target_value': active_goal.target_value,
            'current_value': current_val,
            'percent': round(current_val / max(active_goal.target_value, 1) * 100, 1),
            'unit': active_goal.unit or 'IOCs',
        }

    return {
        'podium': podium,
        'leaderboard': leaderboard,
        'team_goal': team_goal,
    }


def _compute_available_periods(period_type=None, limit=30):
    """Compute list of available report periods based on existing IOC data."""
    oldest_ioc = db.session.query(func.min(IOC.created_at)).scalar()
    if not oldest_ioc:
        return []

    oldest_date = oldest_ioc.date() if hasattr(oldest_ioc, 'date') else oldest_ioc
    today = date.today()
    periods = []

    if period_type is None or period_type == 'day':
        d = today
        for _ in range(min(limit, 30)):
            if d < oldest_date:
                break
            periods.append({
                'label': d.strftime('%b %d, %Y'),
                'date': d.isoformat(),
                'period': 'day',
            })
            d -= timedelta(days=1)

    if period_type is None or period_type == 'week':
        d = today - timedelta(days=today.weekday())
        for _ in range(min(limit, 12)):
            if d < oldest_date:
                break
            end = d + timedelta(days=6)
            periods.append({
                'label': f"{d.strftime('%b %d')} - {end.strftime('%b %d')}",
                'date': d.isoformat(),
                'period': 'week',
            })
            d -= timedelta(days=7)

    if period_type is None or period_type == 'month':
        d = today.replace(day=1)
        for _ in range(min(limit, 12)):
            if d < oldest_date:
                break
            periods.append({
                'label': d.strftime('%B %Y'),
                'date': d.isoformat(),
                'period': 'month',
            })
            if d.month == 1:
                d = d.replace(year=d.year - 1, month=12)
            else:
                d = d.replace(month=d.month - 1)

    return periods
