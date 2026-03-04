"""
Champs Analysis 5.0 - Scoring and analytics.
Scaled scoring: lower points per IOC so yearly totals stay manageable; YARA points by rule quality (10-50).
"""
import json
import re
from datetime import date, datetime, timedelta
from collections import defaultdict
from sqlalchemy import func

# Points per action type (scaled: ~10k IOCs/year -> ~20k points instead of 100k+)
IOC_DEFAULT = 2
IOC_WITH_CAMPAIGN = 3
YARA_DEFAULT = 25   # fallback when quality not computed
YARA_MIN = 10
YARA_MAX = 50
DELETION = 1
STREAK_DAYS = 3
STREAK_BONUS_PERCENT = 10
SCORING_SMART = '8'
# Per-badge: max days of inactivity before this badge is lost. Analyst loses badges gradually, not all at once.
# Streak badges (on_fire, warm_streak): 0 = badge disappears as soon as the streak is broken (one day without activity).
# Keys are badge IDs; value = if (days since last activity) > this, the badge is not shown. Default 30.
BADGE_INACTIVITY_DAYS = {
    'on_fire': 0,      # streak broken (no activity today) → badge gone
    'warm_streak': 0,  # streak broken → badge gone
    'night_owl': 7,
    'early_bird': 7,
    'weekend_warrior': 7,
    'consistent': 10,
    'ever_present': 14,
    'clean_slate': 14,
    'janitor': 21,
    'cleanup_crew': 21,
    'team_player': 21,
    'campaign_master': 30,
    'rare_find': 21,
    'dedicated': 30,
    'veteran': 45,
    'yara_rookie': 21,
    'yara_master': 30,
    'yara_legend': 45,
    'hash_hunter': 21,
    'domain_scout': 21,
    'ip_tracker': 21,
    'url_surfer': 21,
    'phish_buster': 21,
    'triple_threat': 21,
    'all_rounder': 30,
}
BADGE_INACTIVITY_DEFAULT_DAYS = 30  # for any badge not in the dict

# Smart Effort (#8): aggressive decay — max 7 days, badges disappear fast to enforce continuous activity.
BADGE_INACTIVITY_DAYS_SMART = {
    'on_fire': 0,
    'warm_streak': 0,
    'night_owl': 1,
    'early_bird': 1,
    'weekend_warrior': 1,
    'clean_slate': 3,
    'janitor': 3,
    'cleanup_crew': 3,
    'rare_find': 3,
    'team_player': 3,
    'hash_hunter': 3,
    'domain_scout': 3,
    'ip_tracker': 3,
    'url_surfer': 3,
    'phish_buster': 3,
    'consistent': 5,
    'dedicated': 5,
    'triple_threat': 5,
    'all_rounder': 5,
    'campaign_master': 5,
    'yara_rookie': 5,
    'yara_master': 5,
    'ever_present': 7,
    'veteran': 7,
    'yara_legend': 7,
}
BADGE_INACTIVITY_SMART_DEFAULT_DAYS = 7

# Level thresholds: many levels (25), harder early step, growing gaps. Level 2 ≈ 100 IOCs.
LEVEL_THRESHOLDS = [
    0, 200, 450, 750, 1100, 1500, 2000, 2600, 3300, 4100, 5000,
    6100, 7400, 9000, 10900, 13100, 15600, 18500, 21800, 25500, 29700,
    34400, 39600, 45400, 51800, 59000
]

# Nickname by dominant IOC type
NICKNAMES = {
    'IP': ('🛡️', 'Network Hunter'),
    'Domain': ('🌐', 'Domain Scout'),
    'Hash': ('⚔️', 'Malware Slayer'),
    'URL': ('🔗', 'URL Tracker'),
    'YARA': ('🔓', 'Code Breaker'),
    'Email': ('📧', 'Phish Hunter'),
}


def _to_date(val):
    """Convert datetime/date to date for consistent comparison."""
    if val is None:
        return None
    if isinstance(val, date) and not isinstance(val, datetime):
        return val
    if hasattr(val, 'date'):
        return val.date()
    return val


def compute_ioc_points(ioc_type, campaign_id):
    """Return points for one IOC (scaled: 2 default, 3 if linked to campaign)."""
    if campaign_id:
        return IOC_WITH_CAMPAIGN
    return IOC_DEFAULT


SMART_COMMENT_MIN_LEN = 10
SMART_DUPLICATE_THRESHOLD = 3


def _compute_smart_ioc_points(method, comment, campaign_id, analyst_key, day, comment_counts):
    """
    Smart Effort (#8) IOC scoring.
    Single submit: 2 base. Bulk: 1 base.
    +1 for meaningful comment (>10 chars, not duplicated 3+ times in same batch/day).
    +1 for campaign link.
    Range: 1 (lazy bulk) to 4 (single + unique comment + campaign).
    """
    is_bulk = method in ('csv', 'txt', 'paste', 'import')
    pts = 1 if is_bulk else IOC_DEFAULT
    has_comment = len(comment) >= SMART_COMMENT_MIN_LEN
    if has_comment:
        is_dup = False
        if is_bulk and day:
            key = analyst_key + '|' + str(day)
            is_dup = comment_counts.get(key, {}).get(comment, 0) >= SMART_DUPLICATE_THRESHOLD
        if not is_dup:
            pts += 1
    if campaign_id:
        pts += 1
    return pts


def _build_smart_comment_counts(ioc_rows):
    """
    Pre-scan IOC rows to count comment occurrences per analyst+day for bulk submissions.
    Returns nested dict: { 'analyst|date': { comment_text: count } }.
    ioc_rows: iterable of dicts with keys 'analyst', 'created_at', 'comment', 'submission_method'.
    """
    counts = defaultdict(lambda: defaultdict(int))
    for r in ioc_rows:
        method = r.get('submission_method') or 'single'
        if method == 'single':
            continue
        d = _to_date(r['created_at'])
        c = (r.get('comment') or '').strip()
        if d and c:
            a = (r.get('analyst') or 'unknown').lower()
            counts[a + '|' + str(d)][c] += 1
    return counts


def _score_ioc_rows(ioc_rows, scoring_method, comment_counts=None):
    """
    Score a list of IOC row dicts. Returns list of (analyst, date, points, user_id) tuples.
    For Smart Effort uses _compute_smart_ioc_points; otherwise compute_ioc_points.
    """
    smart = scoring_method == SCORING_SMART
    results = []
    for r in ioc_rows:
        analyst = (r.get('analyst') or 'unknown').lower()
        d = _to_date(r['created_at'])
        if smart:
            comment = (r.get('comment') or '').strip()
            method = r.get('submission_method') or 'single'
            pts = _compute_smart_ioc_points(method, comment, r.get('campaign_id'), analyst, d, comment_counts or {})
        else:
            pts = compute_ioc_points(r.get('type'), r.get('campaign_id'))
        results.append((analyst, d, pts, r.get('user_id')))
    return results


def _compute_yara_points(qp, status, scoring_method):
    """Return final YARA points, applying Smart Effort pending penalty if needed."""
    pts = (qp if qp is not None else YARA_DEFAULT)
    pts = max(YARA_MIN, min(YARA_MAX, pts))
    if scoring_method == SCORING_SMART and status != 'approved':
        pts = YARA_MIN
    return pts


def compute_yara_quality_points(content):
    """
    Return points 10-50 for a YARA rule based on content quality (heuristic).
    More strings and more complex condition -> higher score.
    """
    if not content or not isinstance(content, str):
        return YARA_DEFAULT
    text = content.strip()
    # Count string definitions (e.g. $a = "...", $foo = { ... })
    string_defs = len(re.findall(r'\$\w+\s*=', text))
    # Find condition section and measure complexity
    cond_match = re.search(r'\bcondition\s*:\s*([\s\S]*?)(?=\s*(?:meta\s*:|\}|$))', text, re.IGNORECASE)
    cond_block = (cond_match.group(1) or '').strip()
    cond_len = len(cond_block)
    cond_keywords = len(re.findall(r'\b(?:and|or|not|any|all|of|them)\b', cond_block, re.IGNORECASE))
    # Heuristic: more strings + longer/complex condition -> higher tier
    score = 10
    if string_defs >= 15 or (cond_len > 200 and cond_keywords >= 4):
        score = min(YARA_MAX, 36 + (string_defs // 5) + min(14, cond_keywords))
    elif string_defs >= 6 or cond_len > 80 or cond_keywords >= 2:
        score = min(35, 19 + min(string_defs, 10) + min(cond_keywords * 2, 10))
    else:
        score = min(18, 10 + string_defs + min(cond_len // 20, 5))
    return max(YARA_MIN, min(YARA_MAX, score))


def compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent=None, user_id_map=None, scoring_method='1', exclude_usernames=None, start_dt=None, end_dt=None):
    """
    Compute weighted scores for all analysts using Champs 5.0 scoring.
    Includes deletion points from ActivityEvent (event_type='ioc_deletion', payload was_expired=True).
    scoring_method: '1'-'8' (admin setting). Smart Effort (#8) gives full YARA points only
    for approved rules; pending rules receive YARA_MIN.
    exclude_usernames: set of lowercase usernames to filter out (e.g. MISP sync user).
    start_dt, end_dt: optional datetime range to filter IOCs/YARA by created_at/uploaded_at (for period reports).
    """
    _excluded = {u.lower() for u in (exclude_usernames or [])}
    today = date.today()
    analyst_daily = defaultdict(lambda: defaultdict(int))
    analyst_iocs = defaultdict(int)
    analyst_yara = defaultdict(int)
    analyst_deletions = defaultdict(int)
    analyst_deletions_total = defaultdict(int)
    analyst_last = {}
    analyst_user_id = {}

    # IOC points — prefer user_id -> username so invalid analyst strings (e.g. "soc") count under real user
    id_to_username = {u.id: (u.username or '').lower() for u in User.query.all() if u.username}
    smart = scoring_method == SCORING_SMART
    ioc_cols = [IOC.analyst, IOC.type, IOC.campaign_id, IOC.user_id, IOC.created_at]
    if smart:
        ioc_cols += [IOC.comment, IOC.submission_method]
    ioc_q = db.session.query(*ioc_cols)
    if start_dt is not None:
        ioc_q = ioc_q.filter(IOC.created_at >= start_dt)
    if end_dt is not None:
        ioc_q = ioc_q.filter(IOC.created_at <= end_dt)
    raw_rows = ioc_q.all()
    col_names = ['analyst', 'type', 'campaign_id', 'user_id', 'created_at']
    if smart:
        col_names += ['comment', 'submission_method']
    ioc_dicts = [dict(zip(col_names, r)) for r in raw_rows]

    # Resolve analyst via user_id -> username mapping
    for rd in ioc_dicts:
        uid = rd.get('user_id')
        rd['analyst'] = (id_to_username.get(uid) if uid else None) or (rd['analyst'] or 'unknown')

    comment_counts = _build_smart_comment_counts(ioc_dicts) if smart else {}
    scored = _score_ioc_rows(ioc_dicts, scoring_method, comment_counts)

    for analyst, d, pts, uid in scored:
        if d:
            analyst_daily[analyst][d] = analyst_daily[analyst].get(d, 0) + pts
            analyst_last[analyst] = max(analyst_last.get(analyst, d), d) if analyst_last.get(analyst) else d
        analyst_iocs[analyst] += 1
        if uid:
            analyst_user_id[analyst] = uid

    # YARA points (per-rule quality 10-50, or YARA_DEFAULT if not set)
    yara_q = db.session.query(YaraRule.analyst, YaraRule.uploaded_at, YaraRule.quality_points, YaraRule.status)
    if start_dt is not None:
        yara_q = yara_q.filter(YaraRule.uploaded_at >= start_dt)
    if end_dt is not None:
        yara_q = yara_q.filter(YaraRule.uploaded_at <= end_dt)
    yara_rows = yara_q.all()
    for analyst, uploaded_at, qp, status in yara_rows:
        a = (analyst or 'unknown').lower()
        pts = _compute_yara_points(qp, status, scoring_method)
        d = _to_date(uploaded_at)
        if d:
            analyst_daily[a][d] = analyst_daily[a].get(d, 0) + pts
        analyst_last[a] = max(analyst_last.get(a, d), d) if analyst_last.get(a) else d
        analyst_yara[a] = analyst_yara[a] + 1

    # Deletion points (ActivityEvent: ioc_deletion)
    # - Display count (deletion_count): all deletions
    # - Score points: only expired IOCs (cleanup/hygiene)
    # - Badges (clean_slate, janitor, etc.): only expired
    if ActivityEvent:
        del_q = db.session.query(
            ActivityEvent.user_id,
            ActivityEvent.payload,
            ActivityEvent.created_at,
        ).filter(ActivityEvent.event_type == 'ioc_deletion')
        if start_dt is not None:
            del_q = del_q.filter(ActivityEvent.created_at >= start_dt)
        if end_dt is not None:
            del_q = del_q.filter(ActivityEvent.created_at <= end_dt)
        del_rows = del_q.all()
        users = {u.id: u.username.lower() for u in User.query.all() if u.username}
        for uid, payload, created_at in del_rows:
            try:
                p = json.loads(payload or '{}')
                was_expired = p.get('was_expired', False)
            except (json.JSONDecodeError, TypeError):
                was_expired = False
            a = users.get(uid, 'unknown')
            analyst_deletions_total[a] = analyst_deletions_total.get(a, 0) + 1
            if was_expired:
                analyst_deletions[a] = analyst_deletions.get(a, 0) + 1
                d = _to_date(created_at)
                if d:
                    analyst_daily[a][d] = analyst_daily[a].get(d, 0) + DELETION
                    analyst_last[a] = max(analyst_last.get(a, d), d) if analyst_last.get(a) else d
            if uid:
                analyst_user_id[a] = uid

    # Map analyst -> user_id
    if user_id_map is None:
        user_id_map = {u.username.lower(): u.id for u in User.query.all() if u.username}
    for a in analyst_daily:
        if a not in analyst_user_id and a in user_id_map:
            analyst_user_id[a] = user_id_map[a]
    for a in analyst_deletions:
        if a not in analyst_user_id and a in user_id_map:
            analyst_user_id[a] = user_id_map[a]
    for a in analyst_deletions_total:
        if a not in analyst_user_id and a in user_id_map:
            analyst_user_id[a] = user_id_map[a]

    # Compute total score + streak (use end_dt.date() as reference when filtering by period)
    streak_ref = end_dt.date() if end_dt else today
    result = []
    all_analysts = set(analyst_daily.keys()) | set(analyst_deletions.keys()) | set(analyst_deletions_total.keys())
    if _excluded:
        all_analysts -= _excluded
    for analyst in all_analysts:
        daily = analyst_daily.get(analyst, {})
        base_score = sum(daily.values())
        streak = 0
        d = streak_ref
        for _ in range(90):
            if d in daily and daily[d] > 0:
                streak += 1
                d = d - timedelta(days=1)
            else:
                break
        streak_bonus = int(base_score * STREAK_BONUS_PERCENT / 100) if streak >= STREAK_DAYS else 0
        total_score = base_score + streak_bonus

        last_d = analyst_last.get(analyst)
        last_str = last_d.strftime('%Y-%m-%d') if last_d else 'N/A'

        result.append({
            'analyst': analyst,
            'user_id': analyst_user_id.get(analyst),
            'score': total_score,
            'total_iocs': analyst_iocs.get(analyst, 0),
            'yara_count': analyst_yara.get(analyst, 0),
            'deletion_count': analyst_deletions_total.get(analyst, 0),
            'last_activity': last_str,
            'streak_days': streak,
            'streak_bonus_applied': streak_bonus,
        })

    result.sort(key=lambda x: x['score'], reverse=True)
    for idx, r in enumerate(result, 1):
        r['rank'] = idx
    return result


def get_rank_trend(db, ChampRankSnapshot, user_id, current_rank):
    """Compare current rank to yesterday's."""
    if not user_id:
        return 0, 'same'
    yesterday = date.today() - timedelta(days=1)
    snap = ChampRankSnapshot.query.filter_by(user_id=user_id, snapshot_date=yesterday).first()
    if not snap:
        return 0, 'same'
    delta = snap.rank - current_rank
    if delta > 0:
        return delta, 'up'
    if delta < 0:
        return delta, 'down'
    return 0, 'same'


def save_daily_rank_snapshots(db, IOC, YaraRule, User, ChampRankSnapshot, ActivityEvent=None, scoring_method='1', exclude_usernames=None):
    """Save today's rank snapshot for each analyst. Idempotent (skip if already saved).
    Returns (did_save: bool, rows: list or None). If did_save, rows are the computed scores; else rows is None."""
    today = date.today()
    if ChampRankSnapshot.query.filter_by(snapshot_date=today).first():
        return False, None  # already saved today
    rows = compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent, scoring_method=scoring_method, exclude_usernames=exclude_usernames)
    for r in rows:
        uid = r.get('user_id')
        if not uid:
            continue
        existing = ChampRankSnapshot.query.filter_by(user_id=uid, snapshot_date=today).first()
        if existing:
            existing.rank = r['rank']
            existing.score = r['score']
        else:
            db.session.add(ChampRankSnapshot(user_id=uid, rank=r['rank'], score=r['score'], snapshot_date=today))
    try:
        db.session.commit()
        return True, rows
    except Exception:
        db.session.rollback()
        return False, None


def get_rank_change_events(db, ChampRankSnapshot, User, rows_today):
    """After saving today's snapshot: compare with yesterday and return list of rank-change events.
    Each event: {overtaker_user_id, overtaken_user_id, new_rank, old_rank} for ticker message."""
    yesterday = date.today() - timedelta(days=1)
    snap_yesterday = {
        s.user_id: s.rank
        for s in ChampRankSnapshot.query.filter_by(snapshot_date=yesterday).all()
    }
    if not snap_yesterday:
        return []
    # Build yesterday rank -> user_id (who was at each rank)
    rank_to_user_yesterday = {}
    for uid, r in snap_yesterday.items():
        rank_to_user_yesterday[r] = uid
    events = []
    for r in rows_today:
        uid = r.get('user_id')
        if not uid:
            continue
        new_rank = r['rank']
        old_rank = snap_yesterday.get(uid)
        if old_rank is None or new_rank >= old_rank:
            continue
        # Improved: new_rank < old_rank. Who did they overtake? The one who was at new_rank yesterday.
        overtaken_uid = rank_to_user_yesterday.get(new_rank)
        if overtaken_uid and overtaken_uid != uid:
            events.append({
                'overtaker_user_id': uid,
                'overtaken_user_id': overtaken_uid,
                'new_rank': new_rank,
                'old_rank': old_rank,
            })
    return events


def _get_level_and_xp(score):
    """Return (level, xp_in_level, xp_to_next_level). Level is 1-based."""
    level = 1
    for i, thresh in enumerate(LEVEL_THRESHOLDS):
        if score >= thresh:
            level = i + 1
    idx = min(level - 1, len(LEVEL_THRESHOLDS) - 1)
    current_thresh = LEVEL_THRESHOLDS[idx]
    next_thresh = LEVEL_THRESHOLDS[idx + 1] if idx + 1 < len(LEVEL_THRESHOLDS) else current_thresh + 10000
    xp_in_level = score - current_thresh
    xp_to_next = next_thresh - score
    return level, xp_in_level, max(0, xp_to_next), next_thresh - current_thresh


def _get_nickname(ioc_type_counts):
    """Return (emoji, name) based on dominant IOC type."""
    if not ioc_type_counts:
        return ('🎯', 'Threat Hunter')
    dominant = max(ioc_type_counts.items(), key=lambda x: x[1])[0]
    return NICKNAMES.get(dominant, ('🎯', 'Threat Hunter'))


def _get_badges(db, IOC, YaraRule, ActivityEvent, analyst_lower, user_id, analyst_daily, analyst_deletions, scoring_method='1'):
    """Return list of badge keys. Trophy Cabinet: 18+ badges for analyst activity.
    Each badge is lost after N days of no activity (see BADGE_INACTIVITY_DAYS). Badges are lost gradually.
    scoring_method '8' (Smart Effort) uses aggressive decay (max 7 days)."""
    today = date.today()
    last_activity_date = None

    last_ioc = db.session.query(func.max(IOC.created_at)).filter(
        func.lower(IOC.analyst) == analyst_lower
    ).scalar()
    if last_ioc:
        d = _to_date(last_ioc)
        if d and (last_activity_date is None or d > last_activity_date):
            last_activity_date = d
    last_yara = db.session.query(func.max(YaraRule.uploaded_at)).filter(
        func.lower(YaraRule.analyst) == analyst_lower
    ).scalar()
    if last_yara:
        d = _to_date(last_yara)
        if d and (last_activity_date is None or d > last_activity_date):
            last_activity_date = d
    if user_id and ActivityEvent:
        last_del = db.session.query(func.max(ActivityEvent.created_at)).filter(
            ActivityEvent.event_type == 'ioc_deletion', ActivityEvent.user_id == user_id
        ).scalar()
        if last_del:
            d = _to_date(last_del)
            if d and (last_activity_date is None or d > last_activity_date):
                last_activity_date = d

    if last_activity_date is None:
        return []
    days_since_last = (today - last_activity_date).days

    if scoring_method == SCORING_SMART:
        _decay_dict = BADGE_INACTIVITY_DAYS_SMART
        _decay_default = BADGE_INACTIVITY_SMART_DEFAULT_DAYS
    else:
        _decay_dict = BADGE_INACTIVITY_DAYS
        _decay_default = BADGE_INACTIVITY_DEFAULT_DAYS

    def add_badge(badge_key):
        limit = _decay_dict.get(badge_key, _decay_default)
        if days_since_last <= limit:
            badges.append(badge_key)

    badges = []
    daily = analyst_daily.get(analyst_lower, {})

    # --- Streak & time-based ---
    streak = 0
    d = today
    for _ in range(30):
        if d in daily and daily[d] > 0:
            streak += 1
            d = d - timedelta(days=1)
        else:
            break
    if streak >= 5:
        add_badge('on_fire')
    if streak >= 3 and streak < 5:
        add_badge('warm_streak')

    night_hours = {0, 1, 2, 3, 4, 22, 23}
    early_hours = {5, 6, 7}
    has_night = False
    has_early = False
    has_weekend = False
    ioc_rows = db.session.query(IOC.created_at, IOC.type, IOC.campaign_id).filter(
        func.lower(IOC.analyst) == analyst_lower
    ).all()
    type_counts = defaultdict(int)
    campaign_linked = 0
    for created_at, ioc_type, campaign_id in ioc_rows:
        if ioc_type:
            type_counts[ioc_type] += 1
        if campaign_id:
            campaign_linked += 1
        if created_at:
            if getattr(created_at, 'hour', None) in night_hours:
                has_night = True
            if getattr(created_at, 'hour', None) in early_hours:
                has_early = True
            wd = getattr(created_at, 'weekday', lambda: None)()
            if wd is not None and wd in (4, 5):  # Friday, Saturday
                has_weekend = True
    yara_rows = db.session.query(YaraRule.uploaded_at).filter(func.lower(YaraRule.analyst) == analyst_lower).all()
    for (t,) in yara_rows:
        if t:
            if getattr(t, 'hour', None) in night_hours:
                has_night = True
            if getattr(t, 'hour', None) in early_hours:
                has_early = True
            if getattr(t, 'weekday', lambda: None)() in (4, 5):  # Friday, Saturday
                has_weekend = True
    if user_id and ActivityEvent:
        for (t,) in db.session.query(ActivityEvent.created_at).filter(
            ActivityEvent.event_type == 'ioc_deletion', ActivityEvent.user_id == user_id
        ).all():
            if t and getattr(t, 'hour', None) in night_hours:
                has_night = True
                break
    if has_night:
        add_badge('night_owl')
    if has_early:
        add_badge('early_bird')
    if has_weekend:
        add_badge('weekend_warrior')

    total_iocs = sum(type_counts.values())
    # Rare Find: first-ever in system (new country GEO, new TLD, or new email domain)
    if user_id:
        has_rare = db.session.query(IOC).filter(IOC.user_id == user_id, IOC.rare_find_type.isnot(None)).first() is not None
    else:
        has_rare = db.session.query(IOC).filter(func.lower(IOC.analyst) == analyst_lower, IOC.rare_find_type.isnot(None)).first() is not None
    if has_rare:
        add_badge('rare_find')
    if total_iocs >= 30:
        add_badge('dedicated')
    if total_iocs >= 80:
        add_badge('veteran')

    del_count = analyst_deletions.get(analyst_lower, 0)
    if del_count >= 1:
        add_badge('clean_slate')
    if del_count >= 5:
        add_badge('janitor')
    if del_count >= 15:
        add_badge('cleanup_crew')

    if campaign_linked >= 1:
        add_badge('team_player')
    if campaign_linked >= 10:
        add_badge('campaign_master')

    yara_count = db.session.query(YaraRule).filter(func.lower(YaraRule.analyst) == analyst_lower).count()
    if yara_count >= 1:
        add_badge('yara_rookie')
    if yara_count >= 3:
        add_badge('yara_master')
    if yara_count >= 8:
        add_badge('yara_legend')

    if type_counts.get('Hash', 0) >= 10:
        add_badge('hash_hunter')
    if type_counts.get('Domain', 0) >= 15:
        add_badge('domain_scout')
    if type_counts.get('IP', 0) >= 25:
        add_badge('ip_tracker')
    if type_counts.get('URL', 0) >= 10:
        add_badge('url_surfer')
    if type_counts.get('Email', 0) >= 5:
        add_badge('phish_buster')

    distinct_types = sum(1 for c in type_counts.values() if c > 0)
    if distinct_types >= 3:
        add_badge('triple_threat')
    if distinct_types >= 5:
        add_badge('all_rounder')

    active_days = len(daily)
    if active_days >= 7:
        add_badge('consistent')
    if active_days >= 15:
        add_badge('ever_present')

    return badges


def _compute_team_daily_totals(db, IOC, YaraRule, ActivityEvent, today, days_back=30, scoring_method='1'):
    """Return dict date -> total points (all analysts) for last days_back days. Used for team average in Spotlight."""
    team_daily = defaultdict(int)
    start = today - timedelta(days=days_back)
    smart = scoring_method == SCORING_SMART
    ioc_team_cols = [IOC.created_at, IOC.type, IOC.campaign_id]
    if smart:
        ioc_team_cols += [IOC.analyst, IOC.comment, IOC.submission_method]
    raw_rows = db.session.query(*ioc_team_cols).filter(
        IOC.created_at >= datetime.combine(start, datetime.min.time())
    ).all()
    col_names = ['created_at', 'type', 'campaign_id']
    if smart:
        col_names += ['analyst', 'comment', 'submission_method']
    ioc_dicts = [dict(zip(col_names, r)) for r in raw_rows]

    comment_counts = _build_smart_comment_counts(ioc_dicts) if smart else {}
    scored = _score_ioc_rows(ioc_dicts, scoring_method, comment_counts)
    for _analyst, d, pts, _uid in scored:
        if d:
            team_daily[d] = team_daily.get(d, 0) + pts

    yara_rows = db.session.query(YaraRule.uploaded_at, YaraRule.quality_points, YaraRule.status).filter(
        YaraRule.uploaded_at >= datetime.combine(start, datetime.min.time())
    ).all()
    for uploaded_at, qp, status in yara_rows:
        d = _to_date(uploaded_at)
        if d:
            team_daily[d] = team_daily.get(d, 0) + _compute_yara_points(qp, status, scoring_method)
    if ActivityEvent:
        del_rows = db.session.query(ActivityEvent.created_at, ActivityEvent.payload).filter(
            ActivityEvent.event_type == 'ioc_deletion',
            ActivityEvent.created_at >= datetime.combine(start, datetime.min.time())
        ).all()
        for created_at, payload in del_rows:
            try:
                if json.loads(payload or '{}').get('was_expired'):
                    d = _to_date(created_at)
                    if d:
                        team_daily[d] = team_daily.get(d, 0) + DELETION
            except (json.JSONDecodeError, TypeError):
                pass
    return dict(team_daily)


def get_analyst_detail(db, IOC, YaraRule, User, UserProfile, ActivityEvent, user_id, analyst_username, scoring_method='1', misp_sync_username=None):
    """
    Return full analyst detail for Spotlight: nickname, level, XP, activity_per_day, badges, team_avg_per_day.
    analyst_username is fallback when user_id maps to user.
    misp_sync_username: if provided, include misp_per_day (IOC count per day for the MISP sync user).
    """
    rows = compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent, scoring_method=scoring_method)
    analyst_lower = (analyst_username or '').lower()
    row = None
    for r in rows:
        if r.get('user_id') == user_id or (r['analyst'] == analyst_lower):
            row = r
            analyst_lower = r['analyst']
            break
    if not row:
        return None

    # IOC type breakdown for nickname
    ioc_type_counts = defaultdict(int)
    if user_id:
        iocs = db.session.query(IOC.type).filter(IOC.user_id == user_id).all()
    else:
        iocs = db.session.query(IOC.type).filter(func.lower(IOC.analyst) == analyst_lower).all()
    for (t,) in iocs:
        ioc_type_counts[t or 'Unknown'] = ioc_type_counts.get(t, 0) + 1
    # Add YARA
    yara_count = row.get('yara_count', 0)
    if yara_count:
        ioc_type_counts['YARA'] = ioc_type_counts.get('YARA', 0) + yara_count

    emoji, nickname = _get_nickname(dict(ioc_type_counts))
    level, xp_in_level, xp_to_next, level_width = _get_level_and_xp(row['score'])

    # Activity per day (last 30 days)
    analyst_daily = defaultdict(int)
    smart = scoring_method == SCORING_SMART
    ioc_detail_cols = [IOC.created_at, IOC.type, IOC.campaign_id]
    if smart:
        ioc_detail_cols += [IOC.comment, IOC.submission_method]
    raw_rows = db.session.query(*ioc_detail_cols).filter(
        func.lower(IOC.analyst) == analyst_lower
    ).all()
    col_names = ['created_at', 'type', 'campaign_id']
    if smart:
        col_names += ['comment', 'submission_method']
    ioc_dicts = [dict(zip(col_names, r)) for r in raw_rows]
    for rd in ioc_dicts:
        rd['analyst'] = analyst_lower

    comment_counts = _build_smart_comment_counts(ioc_dicts) if smart else {}
    scored = _score_ioc_rows(ioc_dicts, scoring_method, comment_counts)
    for _a, d, pts, _uid in scored:
        if d:
            analyst_daily[d] = analyst_daily.get(d, 0) + pts

    yara_rows = db.session.query(YaraRule.uploaded_at, YaraRule.quality_points, YaraRule.status).filter(func.lower(YaraRule.analyst) == analyst_lower).all()
    for uploaded_at, qp, status in yara_rows:
        d = _to_date(uploaded_at)
        if d:
            analyst_daily[d] = analyst_daily.get(d, 0) + _compute_yara_points(qp, status, scoring_method)
    if ActivityEvent and user_id:
        del_evts = db.session.query(ActivityEvent.created_at, ActivityEvent.payload).filter(
            ActivityEvent.event_type == 'ioc_deletion', ActivityEvent.user_id == user_id
        ).all()
        for created_at, payload in del_evts:
            try:
                p = json.loads(payload or '{}')
                if p.get('was_expired'):
                    d = _to_date(created_at)
                    if d:
                        analyst_daily[d] = analyst_daily.get(d, 0) + DELETION
            except (json.JSONDecodeError, TypeError):
                pass

    today = date.today()
    days_back = 30
    activity_per_day = []
    for i in range(days_back - 1, -1, -1):
        d = today - timedelta(days=i)
        activity_per_day.append({'date': d.strftime('%Y-%m-%d'), 'points': analyst_daily.get(d, 0)})

    # Team average per day (for Spotlight chart overlay)
    team_totals = _compute_team_daily_totals(db, IOC, YaraRule, ActivityEvent, today, days_back, scoring_method=scoring_method)
    num_analysts = max(1, len(rows))
    team_avg_per_day = []
    for i in range(days_back - 1, -1, -1):
        d = today - timedelta(days=i)
        total = team_totals.get(d, 0)
        team_avg_per_day.append({'date': d.strftime('%Y-%m-%d'), 'points': round(total / num_analysts, 1)})

    analyst_deletions = {analyst_lower: row.get('deletion_count', 0)}
    badges = _get_badges(db, IOC, YaraRule, ActivityEvent, analyst_lower, user_id, {analyst_lower: dict(analyst_daily)}, analyst_deletions, scoring_method=scoring_method)

    misp_per_day = None
    if misp_sync_username:
        misp_lower = misp_sync_username.lower()
        start = today - timedelta(days=days_back)
        misp_daily = defaultdict(int)
        misp_ioc_rows = db.session.query(IOC.created_at).filter(
            func.lower(IOC.analyst) == misp_lower,
            IOC.created_at >= datetime.combine(start, datetime.min.time()),
        ).all()
        for (created_at,) in misp_ioc_rows:
            d = _to_date(created_at)
            if d:
                misp_daily[d] = misp_daily.get(d, 0) + 1
        misp_per_day = []
        for i in range(days_back - 1, -1, -1):
            d = today - timedelta(days=i)
            misp_per_day.append({'date': d.strftime('%Y-%m-%d'), 'count': misp_daily.get(d, 0)})

    result = {
        'analyst': analyst_lower,
        'user_id': user_id,
        'score': row['score'],
        'total_iocs': row['total_iocs'],
        'yara_count': row['yara_count'],
        'deletion_count': row.get('deletion_count', 0),
        'streak_days': row['streak_days'],
        'nickname': nickname,
        'nickname_emoji': emoji,
        'level': level,
        'xp_in_level': xp_in_level,
        'xp_to_next': xp_to_next,
        'level_width': level_width,
        'activity_per_day': activity_per_day,
        'team_avg_per_day': team_avg_per_day,
        'badges': badges,
    }
    if misp_per_day is not None:
        result['misp_per_day'] = misp_per_day
    return result


def _week_start(d):
    """Monday as start of week (ISO)."""
    return d - timedelta(days=d.weekday())


def compute_team_goal_current(db, goal, IOC, YaraRule, ActivityEvent):
    """
    Compute current_value for a TeamGoal based on goal_type and period.
    goal_type: ioc_add | yara_add | deletion
    period: weekly | monthly
    Uses rolling window: last 7 days for weekly, last 30 for monthly.
    """
    today = date.today()
    if goal.period == 'weekly':
        start = today - timedelta(days=7)
    else:
        start = today - timedelta(days=30)

    goal_type = getattr(goal, 'goal_type', 'ioc_add') or 'ioc_add'
    if goal_type == 'ioc_add':
        n = db.session.query(IOC).filter(IOC.created_at >= datetime.combine(start, datetime.min.time())).count()
    elif goal_type == 'yara_add':
        n = db.session.query(YaraRule).filter(YaraRule.uploaded_at >= datetime.combine(start, datetime.min.time())).count()
    elif goal_type == 'deletion':
        if ActivityEvent:
            from sqlalchemy import and_
            n = db.session.query(ActivityEvent).filter(
                ActivityEvent.event_type == 'ioc_deletion',
                ActivityEvent.created_at >= datetime.combine(start, datetime.min.time())
            ).count()
        else:
            n = 0
    else:
        n = 0
    return n


def compute_team_goal_for_week(db, goal, IOC, YaraRule, ActivityEvent, week_start_date, week_end_date_inclusive):
    """Count goal_type activity between week_start_date and week_end_date_inclusive (for baseline = previous week)."""
    start_dt = datetime.combine(week_start_date, datetime.min.time())
    end_dt = datetime.combine(week_end_date_inclusive, datetime.max.time().replace(microsecond=0))
    goal_type = getattr(goal, 'goal_type', 'ioc_add') or 'ioc_add'
    if goal_type == 'ioc_add':
        return db.session.query(IOC).filter(IOC.created_at >= start_dt, IOC.created_at <= end_dt).count()
    elif goal_type == 'yara_add':
        return db.session.query(YaraRule).filter(YaraRule.uploaded_at >= start_dt, YaraRule.uploaded_at <= end_dt).count()
    elif goal_type == 'deletion' and ActivityEvent:
        return db.session.query(ActivityEvent).filter(
            ActivityEvent.event_type == 'ioc_deletion',
            ActivityEvent.created_at >= start_dt,
            ActivityEvent.created_at <= end_dt
        ).count()
    return 0
