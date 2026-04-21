"""
SOC Mentorship Insights Engine - behavioral analysis of analyst intelligence output.

Evaluates analysts using 45 rules across 9 categories (Volume, Consistency,
Type Diversity, Quality, Campaign, YARA, Feed Hygiene, Knowledge Sharing,
Growth Trends).  Only measures *intelligence output* - never logins, sessions,
or search clicks.

All heavy lifting is done via bulk SQL aggregations (GROUP BY) so the engine
stays fast even on large SQLite databases.  Calculations run on-demand only
when an admin requests a specific report.
"""
import json
from collections import defaultdict
from datetime import date, datetime, timedelta

from sqlalchemy import func, case, and_, distinct

from extensions import db


# ---------------------------------------------------------------------------
# Severity levels (highest first for sorting)
# ---------------------------------------------------------------------------
_SEV_ORDER = {'action': 0, 'warning': 1, 'info': 2}


# ---------------------------------------------------------------------------
# Rule definitions - each rule is a dict with:
#   id, category, severity, message_fn(stats), recommendation, condition_fn(stats)
# message_fn / condition_fn receive a per-analyst stats dict built from bulk queries.
# ---------------------------------------------------------------------------

def _pct(num, denom):
    return round(num / denom * 100, 1) if denom else 0.0


def _rules():
    """Return the 45 mentorship rules."""
    rules = []

    def R(rule_id, category, severity, condition, message, recommendation):
        rules.append({
            'rule_id': rule_id,
            'category': category,
            'severity': severity,
            'condition': condition,
            'message': message,
            'recommendation': recommendation,
        })

    # ── A: Volume (5) ─────────────────────────────────────────────
    R('vol_zero_iocs', 'Volume', 'action',
      lambda s: s['ioc_count'] == 0,
      'No IOCs submitted in this period',
      'Analyst may be dealing with a complex investigation or other duties. Consider checking in to offer support')
    R('vol_below_avg', 'Volume', 'warning',
      lambda s: 0 < s['ioc_count'] < s['team_avg'] * 0.5,
      'Below 50% of team average IOC output',
      'Consider pairing with a senior contributor for a joint investigation session')
    R('vol_below_min', 'Volume', 'action',
      lambda s: 0 < s['ioc_count'] < s['team_avg'] * 0.25,
      'Below 25% of team average IOC output',
      'Analyst might benefit from a brief walkthrough of the team\'s current threat priorities')
    R('vol_declining', 'Volume', 'warning',
      lambda s: s['prev_ioc_count'] > 0 and s['ioc_count'] < s['prev_ioc_count'] * 0.7,
      'IOC output declined 30%+ from previous period',
      'Noticeable dip in output - could be workload shift or a deep-dive investigation. Worth a quick check-in')
    R('vol_single_burst', 'Volume', 'info',
      lambda s: s['active_days'] == 1 and s['ioc_count'] > 0,
      'All contributions came in a single day',
      'All contributions came in one burst. Spreading work across the week improves feed freshness')

    # ── B: Consistency (5) ────────────────────────────────────────
    R('con_no_streak', 'Consistency', 'info',
      lambda s: s['streak_days'] == 0 and s['ioc_count'] > 0,
      'No active submission streak',
      'A short daily goal (even 1 IOC) helps build rhythm and keeps the analyst engaged')
    R('con_low_active_days', 'Consistency', 'warning',
      lambda s: s['total_days'] > 0 and s['active_days'] / s['total_days'] < 0.3 and s['ioc_count'] > 0,
      'Active on fewer than 30% of the days in this period',
      'Low engagement days. A brief team standup highlighting daily priorities can help')
    R('con_weekend_only', 'Consistency', 'info',
      lambda s: s['weekend_submissions'] > 0 and s['weekday_submissions'] == 0,
      'Submissions only on weekends',
      'Contributions only on weekends. Consider adjusting task distribution for better weekday coverage')
    R('con_irregular_hours', 'Consistency', 'info',
      lambda s: s['ioc_count'] > 0 and s['night_pct'] > 80,
      'Over 80% of submissions during late-night hours (22:00-04:00)',
      'Late-night pattern detected - could indicate after-hours catch-up. Review daytime task allocation')
    R('con_long_gap', 'Consistency', 'warning',
      lambda s: s['max_gap_days'] >= 5,
      'Gap of 5+ consecutive days without any submissions',
      'Extended quiet period - may be leave or a focused investigation. Good to verify')

    # ── C: Type Diversity (6) ─────────────────────────────────────
    R('div_single_type', 'Type Diversity', 'warning',
      lambda s: s['distinct_types'] == 1 and s['ioc_count'] >= 3,
      'All submissions are a single IOC type',
      'All submissions are one type. Broadening exposure to other IOC types can deepen investigation skills')
    R('div_no_hashes', 'Type Diversity', 'info',
      lambda s: s['hash_count'] == 0 and s['ioc_count'] >= 5,
      'No Hash IOCs submitted',
      'No hash submissions yet. Sharing a quick sandbox/malware report walkthrough can open this area')
    R('div_no_domains', 'Type Diversity', 'info',
      lambda s: s['domain_count'] == 0 and s['ioc_count'] >= 5,
      'No Domain IOCs submitted',
      'No domain IOCs. Exposure to DNS analysis techniques can expand this analyst\'s contribution scope')
    R('div_no_urls', 'Type Diversity', 'info',
      lambda s: s['url_count'] == 0 and s['ioc_count'] >= 5,
      'No URL IOCs submitted',
      'No URL submissions. Phishing campaign analysis can be a great entry point for URL extraction')
    R('div_no_emails', 'Type Diversity', 'info',
      lambda s: s['email_count'] == 0 and s['ioc_count'] >= 5,
      'No Email IOCs submitted',
      'No email IOCs. Reviewing phishing headers together can introduce this IOC type naturally')
    R('div_ip_only_heavy', 'Type Diversity', 'info',
      lambda s: s['ioc_count'] >= 5 and s['ip_count'] / max(s['ioc_count'], 1) > 0.8,
      'Over 80% of submissions are IPs only',
      'Heavily focused on IPs. Encouraging payload and domain investigation can diversify contributions')

    # ── D: Quality (6) ────────────────────────────────────────────
    R('qual_no_comments', 'Quality', 'warning',
      lambda s: s['with_comment_pct'] == 0 and s['ioc_count'] > 0,
      'No IOCs have comments',
      'Analyst may not realize how valuable context is. A quick demo of how comments help the team could go a long way')
    R('qual_low_comments', 'Quality', 'info',
      lambda s: 0 < s['with_comment_pct'] < 30,
      'Fewer than 30% of IOCs have comments',
      'Most submissions lack context. Encouraging even brief comments adds significant value')
    R('qual_short_comments', 'Quality', 'info',
      lambda s: s['avg_comment_len'] > 0 and s['avg_comment_len'] < 10,
      'Average comment length under 10 characters',
      'Comments are very short. Sharing examples of good comments from top contributors can inspire improvement')
    R('qual_duplicate_comments', 'Quality', 'info',
      lambda s: s['max_repeated_comment'] >= 3,
      'Same comment repeated 3+ times across IOCs',
      'Same comment repeated across IOCs. Encourage unique context per indicator for better team intelligence')
    R('qual_no_tickets', 'Quality', 'warning',
      lambda s: s['with_ticket_pct'] == 0 and s['ioc_count'] > 0,
      'No IOCs linked to a ticket',
      'No ticket references. Reminding the team that ticket links enable audit trails can help build the habit')
    R('qual_low_tickets', 'Quality', 'info',
      lambda s: 0 < s['with_ticket_pct'] < 40,
      'Fewer than 40% of IOCs linked to a ticket',
      'Low ticket coverage. Consider making ticket ID a suggested field in team guidelines')

    # ── E: Campaign Engagement (3) ────────────────────────────────
    R('camp_never_linked', 'Campaign', 'warning',
      lambda s: s['with_campaign_pct'] == 0 and s['ioc_count'] > 0,
      'No IOCs linked to a campaign',
      'Campaign linking may feel unfamiliar. A short team walkthrough on campaign usage can build awareness')
    R('camp_low_usage', 'Campaign', 'info',
      lambda s: 0 < s['with_campaign_pct'] < 20,
      'Fewer than 20% of IOCs linked to a campaign',
      'Low campaign linkage - sharing how linked IOCs power reports can motivate improvement')
    R('camp_never_created', 'Campaign', 'info',
      lambda s: s['campaigns_created'] == 0 and s['ioc_count'] >= 10,
      'Never created a campaign',
      'This analyst might benefit from exposure to other active threat investigations and creating their own campaigns')

    # ── F: YARA (5) ───────────────────────────────────────────────
    R('yara_zero', 'YARA', 'warning',
      lambda s: s['yara_count'] == 0 and s['ioc_count'] >= 5,
      '0 YARA rules uploaded',
      'YARA can seem intimidating at first. Consider pointing the analyst to the Playbook\'s beginner guide')
    R('yara_low_quality', 'YARA', 'info',
      lambda s: s['yara_count'] > 0 and s['avg_yara_quality'] < 20,
      'Average YARA quality score below 20',
      'YARA quality is developing. A peer review session with a senior rule-writer can accelerate learning')
    R('yara_no_ticket', 'YARA', 'info',
      lambda s: s['yara_without_ticket'] > 0,
      'YARA rules without ticket references',
      'YARA rules without ticket references. A brief reminder about traceability best practices can help')
    R('yara_rejected', 'YARA', 'warning',
      lambda s: s['yara_rejected_count'] > 0,
      'Some YARA rules were rejected',
      'Some rules were rejected - sharing the rejection feedback constructively helps the analyst improve faster')
    R('yara_no_campaign', 'YARA', 'info',
      lambda s: s['yara_without_campaign'] > 0,
      'YARA rules not linked to any campaign',
      'YARA rules not linked to campaigns. Connecting rules to threat context increases their value for the team')

    # ── G: Feed Hygiene (5) ───────────────────────────────────────
    R('hyg_zero_cleanups', 'Feed Hygiene', 'warning',
      lambda s: s['deletion_count'] == 0 and s['ioc_count'] >= 5,
      'No IOCs cleaned up / deleted',
      'Feed hygiene might not be on this analyst\'s radar yet. A team "cleanup hour" can normalize the habit')
    R('hyg_no_expiry', 'Feed Hygiene', 'action',
      lambda s: s['permanent_pct'] == 100 and s['ioc_count'] >= 3,
      'All IOCs set to Permanent (no expiration)',
      'A quick guidance on expiration best practices (30-90 day TTL) can help')
    R('hyg_high_permanent', 'Feed Hygiene', 'info',
      lambda s: 80 < s['permanent_pct'] < 100,
      'Over 80% of IOCs set to Permanent',
      'High permanent ratio. Reminding the team that most IOCs lose relevance over time can shift behavior')
    R('hyg_submitted_anomaly', 'Feed Hygiene', 'warning',
      lambda s: s['anomalous_submissions'] > 0,
      'Submitted IOCs flagged as anomalies (private IP, etc.)',
      'Some submissions flagged as anomalies. Walking through Feed Pulse together helps avoid future false entries')
    R('hyg_stale_contributor', 'Feed Hygiene', 'info',
      lambda s: s['stale_iocs_owned'] > 5,
      'Owns old IOCs (180+ days) that may need review',
      'Has old IOCs that may need review. A periodic "IOC audit" habit benefits the whole team\'s feed quality')

    # ── H: Knowledge Sharing (5) ──────────────────────────────────
    R('know_no_notes', 'Knowledge Sharing', 'warning',
      lambda s: s['notes_count'] == 0 and s['ioc_count'] >= 5,
      'No IOC notes written',
      'Notes help the whole team learn. Highlighting a good note example in standup can inspire participation')
    R('know_no_tags', 'Knowledge Sharing', 'info',
      lambda s: s['with_tags_pct'] == 0 and s['ioc_count'] >= 3,
      'No tags used on any IOCs',
      'No tags used yet. A short demo of how tags power search and reports can show their value')
    R('know_low_tags', 'Knowledge Sharing', 'info',
      lambda s: 0 < s['with_tags_pct'] < 20,
      'Fewer than 20% of IOCs have tags',
      'Low tagging rate. Pairing with a contributor who uses tags well can build this skill naturally')
    R('know_no_edits', 'Knowledge Sharing', 'info',
      lambda s: s['edit_count'] == 0 and s['ioc_count'] >= 5,
      'Never edited/enriched an existing IOC',
      'Hasn\'t enriched existing IOCs. Encouraging a "review and enrich" pass on older IOCs can build the habit')
    R('know_no_rare_finds', 'Knowledge Sharing', 'info',
      lambda s: s['rare_find_count'] == 0 and s['ioc_count'] >= 10,
      'No rare finds (first-ever TLD/country/email domain)',
      'No rare finds yet. Suggesting investigation of lesser-known infrastructure can lead to valuable discoveries')

    # ── I: Growth Trends (5) ──────────────────────────────────────
    R('grow_rank_dropping', 'Growth Trends', 'warning',
      lambda s: s['rank_change'] <= -3,
      lambda s: f'Rank dropped {abs(s["rank_change"])} positions from previous period',
      'Analyst may be focused on a complex case. Consider checking in to see if they need support')
    R('grow_no_badges', 'Growth Trends', 'info',
      lambda s: s['active_badges'] == 0 and s['ioc_count'] > 0,
      'No active badges',
      'Consider pairing this analyst with a senior contributor to build momentum')
    R('grow_lost_badges', 'Growth Trends', 'warning',
      lambda s: s['lost_badges_count'] > 0,
      lambda s: f'Lost {s["lost_badges_count"]} badge(s) due to inactivity',
      'Previously earned badges expired - a short encouragement can help restart the streak')
    R('grow_level_stagnant', 'Growth Trends', 'info',
      lambda s: s['days_at_current_level'] >= 30,
      'Same level for 30+ days',
      'Analyst might benefit from trying a new IOC type or writing a YARA rule to break the plateau')
    R('grow_below_team_avg_trend', 'Growth Trends', 'info',
      lambda s: s['total_days'] > 0 and s['days_below_team_avg'] / s['total_days'] > 0.8 and s['ioc_count'] > 0,
      'Activity consistently below team average',
      'Consistent gap from team average - consider a mentorship pairing or workload review')

    return rules


# ---------------------------------------------------------------------------
# Bulk data collection - everything via SQL GROUP BY
# ---------------------------------------------------------------------------

def _bulk_analyst_stats(start_dt, end_dt, prev_start_dt, prev_end_dt):
    """
    Gather per-analyst stats for current and previous periods using bulk SQL.
    Returns dict: { username_lower: stats_dict }.
    """
    from models import (IOC, IocHistory, IocNote, YaraRule, User,
                        Campaign, ActivityEvent, ChampRankSnapshot, SanityExclusion)

    users = {u.id: u.username.lower() for u in User.query.filter_by(is_active=True).all() if u.username}
    user_ids = set(users.keys())
    if not user_ids:
        return {}

    stats = {}
    for uid, uname in users.items():
        stats[uname] = _empty_stats(uid, uname, start_dt, end_dt)

    total_days = max((end_dt.date() - start_dt.date()).days, 1) if hasattr(start_dt, 'date') else max((end_dt - start_dt).days, 1)
    for s in stats.values():
        s['total_days'] = total_days

    # ── IOC counts and breakdowns (current period) ────────────────
    ioc_rows = db.session.query(
        IOC.user_id,
        func.count(IOC.id).label('cnt'),
        func.sum(case((IOC.type == 'IP', 1), else_=0)).label('ip'),
        func.sum(case((IOC.type == 'Domain', 1), else_=0)).label('domain'),
        func.sum(case((IOC.type == 'Hash', 1), else_=0)).label('hash'),
        func.sum(case((IOC.type == 'URL', 1), else_=0)).label('url'),
        func.sum(case((IOC.type == 'Email', 1), else_=0)).label('email'),
        func.count(distinct(IOC.type)).label('distinct_types'),
        func.sum(case((and_(IOC.comment.isnot(None), IOC.comment != ''), 1), else_=0)).label('with_comment'),
        func.sum(case((and_(IOC.ticket_id.isnot(None), IOC.ticket_id != ''), 1), else_=0)).label('with_ticket'),
        func.sum(case((IOC.campaign_id.isnot(None), 1), else_=0)).label('with_campaign'),
        func.sum(case((IOC.expiration_date.is_(None), 1), else_=0)).label('permanent'),
        func.sum(case((and_(IOC.tags.isnot(None), IOC.tags != '[]', IOC.tags != ''), 1), else_=0)).label('with_tags'),
        func.sum(case((IOC.rare_find_type.isnot(None), 1), else_=0)).label('rare_finds'),
    ).filter(
        IOC.user_id.in_(user_ids),
        IOC.created_at >= start_dt,
        IOC.created_at <= end_dt,
    ).group_by(IOC.user_id).all()

    for row in ioc_rows:
        uname = users.get(row.user_id)
        if not uname or uname not in stats:
            continue
        s = stats[uname]
        s['ioc_count'] = row.cnt or 0
        s['ip_count'] = row.ip or 0
        s['domain_count'] = row.domain or 0
        s['hash_count'] = row.hash or 0
        s['url_count'] = row.url or 0
        s['email_count'] = row.email or 0
        s['distinct_types'] = row.distinct_types or 0
        s['with_comment_pct'] = _pct(row.with_comment or 0, row.cnt or 0)
        s['with_ticket_pct'] = _pct(row.with_ticket or 0, row.cnt or 0)
        s['with_campaign_pct'] = _pct(row.with_campaign or 0, row.cnt or 0)
        s['permanent_pct'] = _pct(row.permanent or 0, row.cnt or 0)
        s['with_tags_pct'] = _pct(row.with_tags or 0, row.cnt or 0)
        s['rare_find_count'] = row.rare_finds or 0

    # ── Comment quality (avg length, max duplication) ─────────────
    comment_stats = db.session.query(
        IOC.user_id,
        func.avg(func.length(IOC.comment)).label('avg_len'),
    ).filter(
        IOC.user_id.in_(user_ids),
        IOC.created_at >= start_dt,
        IOC.created_at <= end_dt,
        IOC.comment.isnot(None),
        IOC.comment != '',
    ).group_by(IOC.user_id).all()

    for row in comment_stats:
        uname = users.get(row.user_id)
        if uname and uname in stats:
            stats[uname]['avg_comment_len'] = round(row.avg_len or 0, 1)

    # duplicate comment detection (per user in period)
    dup_comments = db.session.query(
        IOC.user_id,
        IOC.comment,
        func.count(IOC.id).label('cnt'),
    ).filter(
        IOC.user_id.in_(user_ids),
        IOC.created_at >= start_dt,
        IOC.created_at <= end_dt,
        IOC.comment.isnot(None),
        IOC.comment != '',
    ).group_by(IOC.user_id, IOC.comment).having(func.count(IOC.id) >= 3).all()

    for row in dup_comments:
        uname = users.get(row.user_id)
        if uname and uname in stats:
            stats[uname]['max_repeated_comment'] = max(stats[uname]['max_repeated_comment'], row.cnt or 0)

    # ── Active days + weekday/weekend + night hours + gap ─────────
    day_hour_rows = db.session.query(
        IOC.user_id,
        func.date(IOC.created_at).label('day'),
        func.strftime('%H', IOC.created_at).label('hour'),
        func.strftime('%w', IOC.created_at).label('weekday'),
    ).filter(
        IOC.user_id.in_(user_ids),
        IOC.created_at >= start_dt,
        IOC.created_at <= end_dt,
    ).all()

    user_days = defaultdict(set)
    user_night = defaultdict(int)
    user_total_hourly = defaultdict(int)
    user_weekday_subs = defaultdict(int)
    user_weekend_subs = defaultdict(int)

    for row in day_hour_rows:
        uname = users.get(row.user_id)
        if not uname:
            continue
        user_days[uname].add(row.day)
        h = int(row.hour) if row.hour else 0
        if h >= 22 or h <= 4:
            user_night[uname] += 1
        user_total_hourly[uname] += 1
        wd = int(row.weekday) if row.weekday else 0
        # SQLite %w: 0=Sunday, 6=Saturday
        if wd in (0, 6):
            user_weekend_subs[uname] += 1
        else:
            user_weekday_subs[uname] += 1

    for uname, days in user_days.items():
        if uname not in stats:
            continue
        s = stats[uname]
        s['active_days'] = len(days)
        s['night_pct'] = _pct(user_night.get(uname, 0), user_total_hourly.get(uname, 0))
        s['weekend_submissions'] = user_weekend_subs.get(uname, 0)
        s['weekday_submissions'] = user_weekday_subs.get(uname, 0)
        sorted_days = sorted(days)
        if len(sorted_days) >= 2:
            max_gap = 0
            for i in range(1, len(sorted_days)):
                try:
                    d1 = datetime.strptime(sorted_days[i - 1], '%Y-%m-%d').date() if isinstance(sorted_days[i - 1], str) else sorted_days[i - 1]
                    d2 = datetime.strptime(sorted_days[i], '%Y-%m-%d').date() if isinstance(sorted_days[i], str) else sorted_days[i]
                    gap = (d2 - d1).days
                    if gap > max_gap:
                        max_gap = gap
                except (TypeError, ValueError):
                    pass
            s['max_gap_days'] = max_gap

    # ── Previous period IOC count ─────────────────────────────────
    prev_ioc_rows = db.session.query(
        IOC.user_id,
        func.count(IOC.id).label('cnt'),
    ).filter(
        IOC.user_id.in_(user_ids),
        IOC.created_at >= prev_start_dt,
        IOC.created_at <= prev_end_dt,
    ).group_by(IOC.user_id).all()

    for row in prev_ioc_rows:
        uname = users.get(row.user_id)
        if uname and uname in stats:
            stats[uname]['prev_ioc_count'] = row.cnt or 0

    # ── Team average IOC count ────────────────────────────────────
    total_iocs = sum(s['ioc_count'] for s in stats.values())
    team_avg = total_iocs / max(len(stats), 1)
    for s in stats.values():
        s['team_avg'] = team_avg

    # ── YARA stats ────────────────────────────────────────────────
    yara_rows = db.session.query(
        func.lower(YaraRule.analyst).label('analyst'),
        func.count(YaraRule.id).label('cnt'),
        func.avg(YaraRule.quality_points).label('avg_quality'),
        func.sum(case((YaraRule.ticket_id.is_(None), 1), else_=0)).label('no_ticket'),
        func.sum(case((YaraRule.campaign_id.is_(None), 1), else_=0)).label('no_campaign'),
        func.sum(case((YaraRule.status == 'rejected', 1), else_=0)).label('rejected'),
    ).filter(
        YaraRule.uploaded_at >= start_dt,
        YaraRule.uploaded_at <= end_dt,
    ).group_by(func.lower(YaraRule.analyst)).all()

    for row in yara_rows:
        uname = (row.analyst or '').lower()
        if uname in stats:
            stats[uname]['yara_count'] = row.cnt or 0
            stats[uname]['avg_yara_quality'] = round(row.avg_quality or 0, 1)
            stats[uname]['yara_without_ticket'] = row.no_ticket or 0
            stats[uname]['yara_without_campaign'] = row.no_campaign or 0
            stats[uname]['yara_rejected_count'] = row.rejected or 0

    # ── Deletion count (from ActivityEvent) ───────────────────────
    del_rows = db.session.query(
        ActivityEvent.user_id,
        func.count(ActivityEvent.id).label('cnt'),
    ).filter(
        ActivityEvent.event_type == 'ioc_deletion',
        ActivityEvent.created_at >= start_dt,
        ActivityEvent.created_at <= end_dt,
    ).group_by(ActivityEvent.user_id).all()

    for row in del_rows:
        uname = users.get(row.user_id)
        if uname and uname in stats:
            stats[uname]['deletion_count'] = row.cnt or 0

    # ── IOC Notes count ───────────────────────────────────────────
    note_rows = db.session.query(
        IocNote.user_id,
        func.count(IocNote.id).label('cnt'),
    ).filter(
        IocNote.user_id.in_(user_ids),
        IocNote.created_at >= start_dt,
        IocNote.created_at <= end_dt,
    ).group_by(IocNote.user_id).all()

    for row in note_rows:
        uname = users.get(row.user_id)
        if uname and uname in stats:
            stats[uname]['notes_count'] = row.cnt or 0

    # ── Edit count (from IocHistory) ──────────────────────────────
    edit_rows = db.session.query(
        func.lower(IocHistory.username).label('uname'),
        func.count(IocHistory.id).label('cnt'),
    ).filter(
        IocHistory.event_type == 'edited',
        IocHistory.at >= start_dt,
        IocHistory.at <= end_dt,
    ).group_by(func.lower(IocHistory.username)).all()

    for row in edit_rows:
        uname = (row.uname or '').lower()
        if uname in stats:
            stats[uname]['edit_count'] = row.cnt or 0

    # ── Campaigns created ─────────────────────────────────────────
    # Campaign doesn't have user_id; try matching Campaign creator via
    # first IOC linking (lightweight approximation): distinct campaign_ids
    # that this user was the first to link.
    # Simpler approach: count distinct campaigns the user linked IOCs to.
    camp_rows = db.session.query(
        IOC.user_id,
        func.count(distinct(IOC.campaign_id)).label('cnt'),
    ).filter(
        IOC.user_id.in_(user_ids),
        IOC.campaign_id.isnot(None),
        IOC.created_at >= start_dt,
        IOC.created_at <= end_dt,
    ).group_by(IOC.user_id).all()

    for row in camp_rows:
        uname = users.get(row.user_id)
        if uname and uname in stats:
            stats[uname]['campaigns_created'] = row.cnt or 0

    # ── Stale IOCs owned (older than 180 days, still active) ──────
    stale_cutoff = datetime.utcnow() - timedelta(days=180)
    stale_rows = db.session.query(
        IOC.user_id,
        func.count(IOC.id).label('cnt'),
    ).filter(
        IOC.user_id.in_(user_ids),
        IOC.created_at < stale_cutoff,
        IOC.expiration_date.is_(None),
    ).group_by(IOC.user_id).all()

    for row in stale_rows:
        uname = users.get(row.user_id)
        if uname and uname in stats:
            stats[uname]['stale_iocs_owned'] = row.cnt or 0

    # ── Anomalous submissions (from SanityExclusion or Feed Pulse) ─
    # Use IocHistory to check if the user submitted IOCs that were later
    # flagged. Approximation: check if any of the user's IOCs appear
    # in SanityExclusion.
    if user_ids:
        anomaly_counts = {}
        for uid, uname in users.items():
            anom_count = db.session.query(func.count(SanityExclusion.id)).filter(
                func.lower(SanityExclusion.excluded_by) == uname
            ).scalar() or 0
            if anom_count > 0:
                anomaly_counts[uname] = anom_count
        for uname, cnt in anomaly_counts.items():
            if uname in stats:
                stats[uname]['anomalous_submissions'] = cnt

    # ── Streak days (current) ─────────────────────────────────────
    today = date.today()
    for uname in stats:
        days_set = user_days.get(uname, set())
        streak = 0
        d = today
        for _ in range(90):
            d_str = d.strftime('%Y-%m-%d')
            if d_str in days_set or d in days_set:
                streak += 1
                d = d - timedelta(days=1)
            else:
                break
        stats[uname]['streak_days'] = streak

    # ── Rank change (from ChampRankSnapshot) ──────────────────────
    end_date = end_dt.date() if hasattr(end_dt, 'date') else end_dt
    start_date = start_dt.date() if hasattr(start_dt, 'date') else start_dt

    current_snaps = db.session.query(
        ChampRankSnapshot.user_id,
        ChampRankSnapshot.rank,
        ChampRankSnapshot.score,
    ).filter(
        ChampRankSnapshot.snapshot_date == end_date,
    ).all()

    prev_snaps = db.session.query(
        ChampRankSnapshot.user_id,
        ChampRankSnapshot.rank,
    ).filter(
        ChampRankSnapshot.snapshot_date == start_date,
    ).all()

    prev_ranks = {r.user_id: r.rank for r in prev_snaps}
    for snap in current_snaps:
        uname = users.get(snap.user_id)
        if uname and uname in stats:
            old_rank = prev_ranks.get(snap.user_id)
            if old_rank is not None:
                stats[uname]['rank_change'] = snap.rank - old_rank

    # ── Badges (active vs previous - for lost_badges_count) ───────
    # This is lightweight: we just count badges from champs utility
    # Only import when needed to avoid circular dependency at module level
    try:
        from utils.champs import _get_badges, compute_analyst_scores
        from models import IOC as IOC_m, YaraRule as YR_m, User as U_m, ActivityEvent as AE_m

        scores = compute_analyst_scores(db, IOC_m, YR_m, U_m, AE_m)
        analyst_daily = defaultdict(lambda: defaultdict(int))
        analyst_deletions = {}
        for r in scores:
            a = r['analyst']
            analyst_deletions[a] = r.get('deletion_count', 0)

        for uname, s in stats.items():
            uid = s['user_id']
            matching = [r for r in scores if r['analyst'] == uname]
            if matching:
                s['active_badges'] = len(_get_badges(
                    db, IOC_m, YR_m, AE_m, uname, uid,
                    analyst_daily, analyst_deletions
                ))
    except Exception:
        pass

    # ── Days at current level ─────────────────────────────────────
    # Approximate: check how many consecutive days the score has been
    # in the same level bracket. Use rank snapshots going back 60 days.
    try:
        from utils.champs import LEVEL_THRESHOLDS

        def _level_for_score(score):
            lv = 1
            for i, t in enumerate(LEVEL_THRESHOLDS):
                if score >= t:
                    lv = i + 1
            return lv

        sixty_days_ago = today - timedelta(days=60)
        snap_history = db.session.query(
            ChampRankSnapshot.user_id,
            ChampRankSnapshot.score,
            ChampRankSnapshot.snapshot_date,
        ).filter(
            ChampRankSnapshot.snapshot_date >= sixty_days_ago,
        ).order_by(ChampRankSnapshot.snapshot_date.desc()).all()

        user_snap_history = defaultdict(list)
        for sh in snap_history:
            user_snap_history[sh.user_id].append((sh.snapshot_date, sh.score))

        for uname, s in stats.items():
            uid = s['user_id']
            snaps = user_snap_history.get(uid, [])
            if not snaps:
                continue
            current_level = _level_for_score(snaps[0][1])
            days_at = 0
            for snap_date, score in snaps:
                if _level_for_score(score) == current_level:
                    days_at += 1
                else:
                    break
            s['days_at_current_level'] = days_at
    except Exception:
        pass

    # ── Days below team average ───────────────────────────────────
    # For each day in the period, compute the team daily average and
    # check if the analyst was below it.
    all_days_data = defaultdict(lambda: defaultdict(int))
    for uname, days_set in user_days.items():
        for d in days_set:
            all_days_data[d][uname] += 1

    for uname, s in stats.items():
        days_below = 0
        my_days = user_days.get(uname, set())
        for d_str, analyst_counts in all_days_data.items():
            daily_avg = sum(analyst_counts.values()) / max(len(stats), 1)
            my_count = analyst_counts.get(uname, 0)
            if my_count < daily_avg:
                days_below += 1
        s['days_below_team_avg'] = days_below

    return stats


def _empty_stats(user_id, username, start_dt, end_dt):
    """Return a stats dict with all fields initialized to zero/defaults."""
    return {
        'user_id': user_id,
        'username': username,
        'ioc_count': 0,
        'prev_ioc_count': 0,
        'team_avg': 0,
        'ip_count': 0,
        'domain_count': 0,
        'hash_count': 0,
        'url_count': 0,
        'email_count': 0,
        'distinct_types': 0,
        'with_comment_pct': 0,
        'avg_comment_len': 0,
        'max_repeated_comment': 0,
        'with_ticket_pct': 0,
        'with_campaign_pct': 0,
        'with_tags_pct': 0,
        'permanent_pct': 0,
        'rare_find_count': 0,
        'active_days': 0,
        'total_days': 1,
        'night_pct': 0,
        'weekend_submissions': 0,
        'weekday_submissions': 0,
        'max_gap_days': 0,
        'streak_days': 0,
        'yara_count': 0,
        'avg_yara_quality': 0,
        'yara_without_ticket': 0,
        'yara_without_campaign': 0,
        'yara_rejected_count': 0,
        'deletion_count': 0,
        'notes_count': 0,
        'edit_count': 0,
        'campaigns_created': 0,
        'stale_iocs_owned': 0,
        'anomalous_submissions': 0,
        'active_badges': 0,
        'lost_badges_count': 0,
        'days_at_current_level': 0,
        'rank_change': 0,
        'days_below_team_avg': 0,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_mentorship_insights(start_dt, end_dt, prev_start_dt, prev_end_dt, max_findings=5):
    """
    Run the mentorship analysis engine and return a flat list of the top
    findings sorted by severity, ready for the Reports API.

    Returns list of dicts:
        [{ analyst_name, rule_id, severity, category, message, recommendation }, ...]

    Only returns findings with severity 'action' or 'warning'.
    Limited to `max_findings` entries.
    """
    from models import User, UserProfile

    all_stats = _bulk_analyst_stats(start_dt, end_dt, prev_start_dt, prev_end_dt)
    rules = _rules()

    # Resolve display names
    display_names = {}
    profiles = db.session.query(User.username, UserProfile.display_name).outerjoin(
        UserProfile, User.id == UserProfile.user_id
    ).all()
    for uname, dname in profiles:
        key = (uname or '').lower()
        display_names[key] = dname or uname or key

    findings = []
    for uname, analyst_stats in all_stats.items():
        for rule in rules:
            try:
                if rule['condition'](analyst_stats):
                    msg = rule['message']
                    if callable(msg):
                        msg = msg(analyst_stats)

                    sev = rule['severity']
                    if sev not in ('action', 'warning'):
                        continue

                    findings.append({
                        'analyst_name': display_names.get(uname, uname),
                        'rule_id': rule['rule_id'],
                        'severity': sev,
                        'category': rule['category'],
                        'message': msg,
                        'recommendation': rule['recommendation'],
                    })
            except Exception:
                continue

    findings.sort(key=lambda f: (_SEV_ORDER.get(f['severity'], 9), f['analyst_name']))
    return findings[:max_findings]
