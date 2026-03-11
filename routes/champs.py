"""
Champs and analyst API routes: leaderboard, team goal, ticker, analyst stats/activity, analyst detail.
Register with url_prefix='/api'.
Uses lazy imports from app for shared helpers to avoid circular imports.
"""
import json
from datetime import date, datetime, timedelta, timezone

from flask import Blueprint, request, jsonify, url_for
from flask_login import current_user
from sqlalchemy import func

from extensions import db
from models import User, UserProfile, UserSession, IOC, YaraRule, ActivityEvent, TeamGoal, ChampRankSnapshot
from utils.champs import (
    compute_analyst_scores,
    compute_analyst_scores_aggregated,
    get_rank_trend,
    get_rank_change_events,
    save_daily_rank_snapshots,
    compute_team_goal_current,
    compute_team_goal_for_week,
    get_analyst_detail,
    _week_start,
)
from utils.decorators import login_required, admin_required
from utils.cache import get_cached, set_cached, delete_cached


bp = Blueprint('champs_api', __name__, url_prefix='/api')

CHAMPS_CACHE_TTL = 600   # 10 minutes for leaderboard (extreme-scale friendly)
CHAMPS_ANALYST_CACHE_TTL = 300  # 5 minutes for analyst detail

CHAMPS_SCORING = {
    'ioc_default': 10,
    'ioc_with_campaign': 15,
    'yara_rule': 50,
    'deletion': 5,
    'streak_days': 3,
    'streak_bonus_percent': 10,
}

TICKER_MESSAGES_KEY = 'champs_ticker_messages'
TICKER_MESSAGES_MAX = 5


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


def _get_setting(key, default=''):
    g, = _from_app('_get_setting')
    return g(key, default)


def _set_setting(key, value):
    s, = _from_app('_set_setting')
    s(key, value)


def _log_champs_event(event_type, user_id=None, payload=None):
    """Log activity event for Champs ticker and scoring."""
    _commit_with_retry, = _from_app('_commit_with_retry')
    try:
        ev = ActivityEvent(
            event_type=event_type,
            user_id=user_id,
            payload=json.dumps(payload) if payload is not None else None,
        )
        db.session.add(ev)
        _commit_with_retry()
    except Exception:
        db.session.rollback()


def _avatar_url_for_user(profile, user_id):
    """Return avatar URL for user. Falls back to default avatar if none."""
    if profile and profile.avatar_path:
        return url_for('static', filename=profile.avatar_path)
    idx = ((user_id or 0) % 20) + 1
    return url_for('static', filename=f'avatars/default/avatar_{idx:02d}.svg')


def _goal_milestone_already_logged(goal_id, milestone):
    """Check if we already logged this goal milestone (80 or 100) today."""
    today = datetime.now(timezone.utc).replace(tzinfo=None).date()
    for ev in ActivityEvent.query.filter_by(event_type='goal_progress').order_by(ActivityEvent.created_at.desc()).limit(50):
        try:
            p = json.loads(ev.payload or '{}')
            if p.get('goal_id') == goal_id and p.get('milestone') == milestone:
                ev_date = ev.created_at.date() if ev.created_at and hasattr(ev.created_at, 'date') else None
                if ev_date == today:
                    return True
        except (json.JSONDecodeError, TypeError):
            pass
    return False


def _active_goal_current_percent():
    """Current percent for the active team goal (for ticker). Returns (title, percent) or (None, None)."""
    goal = TeamGoal.query.filter_by(is_active=True).order_by(TeamGoal.updated_at.desc()).first()
    if not goal:
        return None, None
    today = date.today()
    if goal.period == 'weekly':
        this_week_start = _week_start(today)
        last_week_start = this_week_start - timedelta(days=7)
        last_week_end = this_week_start - timedelta(days=1)
        target_value = compute_team_goal_for_week(db, goal, IOC, YaraRule, ActivityEvent, last_week_start, last_week_end)
        current = compute_team_goal_for_week(db, goal, IOC, YaraRule, ActivityEvent, this_week_start, today)
        percent = int(round(100 * current / target_value)) if target_value else 0
    else:
        current = compute_team_goal_current(db, goal, IOC, YaraRule, ActivityEvent)
        target_value = goal.target_value
        percent = min(100, int(100 * current / target_value)) if target_value else 0
    return goal.title, percent


# --- Analyst stats & activity ---

def _champs_excluded_usernames():
    """Build set of usernames excluded from Champs based on admin settings."""
    excluded = set()
    if _get_setting('misp_exclude_from_champs', 'true').lower() == 'true':
        sync_user = (_get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip()
        if sync_user:
            excluded.add(sync_user.lower())
    return excluded or None


@bp.route('/analyst-stats', methods=['GET'])
def get_analyst_stats():
    """Champs 5.0: Analyst stats; scoring method from admin setting (1-8)."""
    method = _get_setting('champs_scoring_method', '1')
    rows = compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent, scoring_method=method, exclude_usernames=_champs_excluded_usernames())
    analyst_list = []
    for r in rows:
        analyst_list.append({
            'user': r['analyst'],
            'user_id': r.get('user_id'),
            'total_iocs': r['total_iocs'],
            'yara_count': r['yara_count'],
            'weighted_score': r['score'],
            'last_activity': r['last_activity'],
            'rank': r['rank'],
            'streak_days': r.get('streak_days', 0),
        })
    return jsonify({'success': True, 'analysts': analyst_list, 'count': len(analyst_list)})


@bp.route('/analyst-activity', methods=['GET'])
def get_analyst_activity():
    """Login frequency, last seen, contribution count per user (from user_sessions)."""
    user_ids = db.session.query(User.id, User.username).all()
    activity = []
    for uid, username in user_ids:
        login_count = UserSession.query.filter_by(user_id=uid).count()
        last_session = UserSession.query.filter_by(user_id=uid).order_by(
            UserSession.login_at.desc()
        ).first()
        last_login = last_session.login_at if last_session else None
        user_obj = db.session.get(User, uid)
        last_seen = user_obj.last_login_at if user_obj and user_obj.last_login_at else last_login
        if last_seen and last_login and last_login > last_seen:
            last_seen = last_login
        ioc_count = IOC.query.filter_by(user_id=uid).count()
        analyst_lower = (username or '').lower()
        yara_count = YaraRule.query.filter(
            func.lower(YaraRule.analyst) == analyst_lower
        ).count()
        activity.append({
            'user_id': uid,
            'username': username,
            'login_count': login_count,
            'last_seen': last_seen.isoformat() if last_seen else None,
            'ioc_count': ioc_count,
            'yara_count': yara_count,
        })
    activity.sort(key=lambda x: (x['login_count'], x['ioc_count']), reverse=True)
    return jsonify({'success': True, 'activity': activity, 'count': len(activity)})


# --- Champs config / leaderboard / team goal / ticker / analyst detail ---

@bp.route('/champs/config', methods=['GET'])
def get_champs_config():
    """Return scoring configuration for Champs Analysis 5.0."""
    return jsonify({
        'success': True,
        'scoring': CHAMPS_SCORING,
    })


def _format_last_activity(val):
    """Format last_activity for display. Handles date, datetime, or str (SQLite may return DATE as string)."""
    if val is None:
        return 'N/A'
    if hasattr(val, 'strftime'):
        return val.strftime('%Y-%m-%d')
    if isinstance(val, str):
        return val[:10] if len(val) >= 10 else val
    return 'N/A'


@bp.route('/champs/leaderboard', methods=['GET'])
def get_champs_leaderboard():
    """Champs 5.0 Ladder: analysts with rank, avatar, display_name, score, trend, medal. Always from computed scores so all analysts appear."""
    method = _get_setting('champs_scoring_method', '1')
    cache_key = f'champs_leaderboard_{method}'
    cached = get_cached(cache_key)
    if cached is not None:
        return jsonify(cached)
    excluded = _champs_excluded_usernames()
    # Always build leaderboard from computed scores (aggregated when no date filter) so every analyst with IOCs appears
    rows = compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent, scoring_method=method, exclude_usernames=excluded)
    did_save, _ = save_daily_rank_snapshots(db, IOC, YaraRule, User, ChampRankSnapshot, ActivityEvent, scoring_method=method, exclude_usernames=excluded, rows=rows)
    if did_save and rows:
        users_by_id = {u.id: u for u in User.query.all()}
        profiles = {p.user_id: p for p in UserProfile.query.all()}
        def _display_name(uid):
            u = users_by_id.get(uid)
            p = profiles.get(uid) if uid else None
            if p and p.display_name:
                return p.display_name
            return u.username if u else 'Unknown'
        for ev in get_rank_change_events(db, ChampRankSnapshot, User, rows):
            _log_champs_event('rank_change', user_id=ev['overtaker_user_id'], payload={
                'overtaken_user_id': ev['overtaken_user_id'],
                'overtaken_name': _display_name(ev['overtaken_user_id']),
                'new_rank': ev['new_rank'],
                'old_rank': ev['old_rank'],
            })
    users_by_id = {u.id: u for u in User.query.all()}
    profiles = {p.user_id: p for p in UserProfile.query.all()}
    leaderboard = []
    for r in rows:
        uid = r.get('user_id')
        user = users_by_id.get(uid) if uid else None
        profile = profiles.get(uid) if uid else None
        username = user.username if user else r['analyst']
        display_name = (profile.display_name if profile and profile.display_name else None) or username
        medal = {1: '🥇', 2: '🥈', 3: '🥉'}.get(r['rank'], '')
        trend_delta, trend_dir = get_rank_trend(db, ChampRankSnapshot, uid, r['rank']) if uid else (0, 'same')
        trend = None
        if trend_dir == 'up':
            trend = f'[ +{trend_delta} ] ▲'
        elif trend_dir == 'down':
            trend = f'[ -{abs(trend_delta)}  ] ▼'
        leaderboard.append({
            'rank': r['rank'],
            'analyst': r['analyst'],
            'user_id': uid,
            'username': username,
            'display_name': display_name,
            'avatar_url': _avatar_url_for_user(profile, uid),
            'score': r['score'],
            'total_iocs': r['total_iocs'],
            'yara_count': r['yara_count'],
            'last_activity': r['last_activity'],
            'medal': medal,
            'trend': trend,
            'streak_days': r.get('streak_days', 0),
        })
    payload = {'success': True, 'leaderboard': leaderboard, 'count': len(leaderboard)}
    set_cached(cache_key, payload, ttl_seconds=CHAMPS_CACHE_TTL)
    return jsonify(payload)


@bp.route('/champs/team-goal', methods=['GET'])
def get_champs_team_goal():
    """Return active team goal. Weekly goals: target = previous week's count (100%), current = this week so far."""
    cache_key = 'champs_team_goal'
    cached = get_cached(cache_key)
    if cached is not None:
        return jsonify(cached)
    goal = TeamGoal.query.filter_by(is_active=True).order_by(TeamGoal.updated_at.desc()).first()
    if not goal:
        out = {'success': True, 'goal': None}
        set_cached(cache_key, out, ttl_seconds=CHAMPS_CACHE_TTL)
        return jsonify(out)
    today = date.today()
    if goal.period == 'weekly':
        this_week_start = _week_start(today)
        last_week_start = this_week_start - timedelta(days=7)
        last_week_end = this_week_start - timedelta(days=1)
        target_value = compute_team_goal_for_week(db, goal, IOC, YaraRule, ActivityEvent, last_week_start, last_week_end)
        current = compute_team_goal_for_week(db, goal, IOC, YaraRule, ActivityEvent, this_week_start, today)
        if target_value and target_value > 0:
            percent = min(100, int(round(100 * current / target_value)))
        else:
            percent = 100 if current > 0 else 0
    else:
        current = compute_team_goal_current(db, goal, IOC, YaraRule, ActivityEvent)
        target_value = goal.target_value
        percent = min(100, int(100 * current / target_value)) if target_value else (100 if current > 0 else 0)
    for milestone in (25, 50, 75, 80, 100):
        if percent >= milestone and not _goal_milestone_already_logged(goal.id, milestone):
            _log_champs_event('goal_progress', user_id=None, payload={
                'goal_id': goal.id, 'title': goal.title, 'percent': percent, 'milestone': milestone,
            })
    payload = {
        'success': True,
        'goal': {
            'id': goal.id,
            'title': goal.title,
            'description': (goal.description or '').strip() or None,
            'target_value': target_value,
            'current_value': current,
            'unit': goal.unit,
            'goal_type': goal.goal_type or 'ioc_add',
            'period': goal.period,
            'percent': percent,
        }
    }
    set_cached(cache_key, payload, ttl_seconds=CHAMPS_CACHE_TTL)
    return jsonify(payload)


@bp.route('/champs/team-goal', methods=['POST'])
@login_required
@admin_required
def set_champs_team_goal():
    """Create or update team goal (admin only)."""
    try:
        data = request.get_json() or {}
        title = (data.get('title') or '').strip()
        description = (data.get('description') or '').strip() or None
        target_value = data.get('target_value')
        unit = (data.get('unit') or '').strip() or None
        goal_type = (data.get('goal_type') or 'ioc_add').strip()
        period = (data.get('period') or 'weekly').strip()
        if not title or target_value is None:
            return jsonify({'success': False, 'message': 'title and target_value required'}), 400
        target_value = int(target_value)
        if target_value < 0:
            return jsonify({'success': False, 'message': 'target_value must be non-negative'}), 400
        if target_value < 1 and period != 'weekly':
            return jsonify({'success': False, 'message': 'target_value must be positive for monthly goals'}), 400
        _commit_with_retry, = _from_app('_commit_with_retry')
        TeamGoal.query.update({'is_active': False})
        goal = TeamGoal(
            title=title,
            description=description,
            target_value=target_value,
            current_value=0,
            unit=unit,
            goal_type=goal_type,
            period=period,
            is_active=True,
        )
        db.session.add(goal)
        _commit_with_retry()
        delete_cached('champs_team_goal')
        _log_champs_event('goal_created', user_id=current_user.id, payload={'goal_id': goal.id, 'title': title})
        return jsonify({'success': True, 'message': 'Team goal set', 'goal_id': goal.id})
    except (ValueError, TypeError) as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/champs/ticker', methods=['GET'])
def get_champs_ticker():
    """Return ticker content: custom messages (if set by admin) or activity events."""
    raw = _get_setting(TICKER_MESSAGES_KEY, '[]')
    try:
        custom = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        custom = []
    if isinstance(custom, list):
        messages = [m for m in custom[:TICKER_MESSAGES_MAX] if isinstance(m, dict) and (m.get('text') or '').strip()]
        if messages:
            return jsonify({'success': True, 'source': 'custom', 'messages': messages})

    limit = min(10, max(6, int(request.args.get('limit', 10))))
    rows = ActivityEvent.query.order_by(ActivityEvent.created_at.desc()).limit(limit).all()
    users = {u.id: (u.username, UserProfile.query.filter_by(user_id=u.id).first()) for u in User.query.all()}
    active_goal_title, active_goal_percent = _active_goal_current_percent()

    def display_name(uid):
        if not uid:
            return 'Unknown'
        uname, prof = users.get(uid, (None, None))
        if prof and prof.display_name:
            return prof.display_name
        return uname or 'Unknown'

    messages = []
    seen_goal_titles = set()
    seen_goal_created = set()
    for ev in rows:
        try:
            p = json.loads(ev.payload or '{}')
        except (json.JSONDecodeError, TypeError):
            p = {}
        ts = ev.created_at.isoformat() if ev.created_at else None
        if ev.event_type == 'ioc_submit':
            messages.append({'text': f"{display_name(ev.user_id)} added a new IOC", 'ts': ts, 'category': 'analyst_success'})
        elif ev.event_type == 'yara_upload':
            fn = p.get('filename', '')
            messages.append({'text': f"{display_name(ev.user_id)} uploaded YARA rule: {fn}", 'ts': ts, 'category': 'analyst_success'})
        elif ev.event_type == 'ioc_deletion':
            if p.get('was_expired'):
                messages.append({'text': f"{display_name(ev.user_id)} removed an expired IOC", 'ts': ts, 'category': 'analyst_success'})
            else:
                ioc_type = p.get('type') or 'IOC'
                val = p.get('value', '') or ''
                messages.append({'text': f"{display_name(ev.user_id)} deleted {ioc_type} {val}", 'ts': ts, 'category': 'negative'})
        elif ev.event_type == 'goal_created':
            title_created = (p.get('title') or '').strip()
            if title_created and title_created not in seen_goal_created:
                seen_goal_created.add(title_created)
                messages.append({'text': f"New team goal: {title_created}", 'ts': ts, 'category': 'team'})
        elif ev.event_type == 'rank_change':
            new_rank = p.get('new_rank', '')
            messages.append({'text': f"{display_name(ev.user_id)} rose to place #{new_rank}", 'ts': ts, 'category': 'analyst_success'})
        elif ev.event_type == 'goal_progress':
            title = p.get('title', 'Team goal')
            if title not in seen_goal_titles:
                seen_goal_titles.add(title)
                if active_goal_title == title and active_goal_percent is not None:
                    pct = active_goal_percent
                else:
                    pct = p.get('percent', 0)
                messages.append({'text': f"Team goal \"{title}\" at {pct}%", 'ts': ts, 'category': 'team'})
    return jsonify({'success': True, 'source': 'activity', 'messages': messages[:limit]})


@bp.route('/champs/ticker-messages', methods=['GET'])
def get_champs_ticker_messages():
    """Return admin-configured ticker messages (up to 5) for the news strip."""
    raw = _get_setting(TICKER_MESSAGES_KEY, '[]')
    try:
        messages = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        messages = []
    if not isinstance(messages, list):
        messages = []
    messages = messages[:TICKER_MESSAGES_MAX]
    return jsonify({'success': True, 'messages': messages})


@bp.route('/champs/ticker-messages', methods=['POST'])
@login_required
@admin_required
def set_champs_ticker_messages():
    """Save admin-configured ticker messages (up to 5). Each item: { text, color, dir } (dir: ltr | rtl)."""
    try:
        data = request.get_json() or {}
        messages = data.get('messages') or []
        if not isinstance(messages, list):
            messages = []
        out = []
        for m in messages[:TICKER_MESSAGES_MAX]:
            if not isinstance(m, dict):
                continue
            text = (m.get('text') or '').strip()
            color = (m.get('color') or '#ffffff').strip()
            if not color.startswith('#'):
                color = '#' + color
            dir_val = (m.get('dir') or m.get('direction') or 'ltr').strip().lower()
            if dir_val not in ('ltr', 'rtl'):
                dir_val = 'ltr'
            out.append({'text': text, 'color': color, 'dir': dir_val})
        _set_setting(TICKER_MESSAGES_KEY, json.dumps(out))
        return jsonify({'success': True, 'messages': out})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/champs/analyst/<int:user_id>', methods=['GET'])
def get_champs_analyst(user_id):
    """Full analyst detail for Spotlight: nickname, level, XP, badges, activity chart data."""
    method = _get_setting('champs_scoring_method', '1')
    cache_key = f'champs_analyst_{user_id}_{method}'
    cached = get_cached(cache_key)
    if cached is not None:
        return jsonify(cached)
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    profile = UserProfile.query.filter_by(user_id=user_id).first()
    misp_user = (_get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip() or None
    detail = get_analyst_detail(db, IOC, YaraRule, User, UserProfile, ActivityEvent, user_id, user.username, scoring_method=method, misp_sync_username=misp_user)
    if not detail:
        today = datetime.now(timezone.utc).replace(tzinfo=None).date()
        activity_per_day = [{'date': (today - timedelta(days=(29 - i))).strftime('%Y-%m-%d'), 'points': 0} for i in range(30)]
        detail = {
            'analyst': user.username.lower(),
            'user_id': user_id,
            'score': 0,
            'total_iocs': 0,
            'yara_count': 0,
            'deletion_count': 0,
            'streak_days': 0,
            'nickname': 'Threat Hunter',
            'nickname_emoji': '🎯',
            'level': 1,
            'xp_in_level': 0,
            'xp_to_next': 100,
            'level_width': 100,
            'activity_per_day': activity_per_day,
            'team_avg_per_day': activity_per_day,
            'badges': [],
            'role_description': (profile.role_description if profile and profile.role_description else None) or '',
        }
    detail['display_name'] = (profile.display_name if profile and profile.display_name else None) or user.username
    detail['avatar_url'] = _avatar_url_for_user(profile, user_id)
    detail['role_description'] = (profile.role_description if profile and profile.role_description else None) or ''
    payload = {'success': True, 'analyst': detail}
    set_cached(cache_key, payload, ttl_seconds=CHAMPS_ANALYST_CACHE_TTL)
    return jsonify(payload)
