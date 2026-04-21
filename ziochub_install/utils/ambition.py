"""
Ambition popup - one personalized message per analyst on login.
Uses same stats as SOC Mentorship; returns first matching of 50 rules (English messages only).
"""
from datetime import datetime, timedelta, timezone

# Default when no rule matches
AMBITION_DEFAULT_MESSAGE = "Pick one goal this week - a tag, a campaign, or YARA - and focus on it."

# 50 rules: (condition_fn(stats) -> bool, message_string). First match wins (order = priority).
def _ambition_rules():
    return [
        # 1-5 Volume
        (lambda s: s.get('ioc_count', 0) == 0,
         "Start fresh this week - submit your first IOC and build momentum."),
        (lambda s: 0 < s.get('ioc_count', 0) < (s.get('team_avg') or 0) * 0.5,
         "You have room to grow - try to match the team average on submissions this week."),
        (lambda s: 0 < s.get('ioc_count', 0) < (s.get('team_avg') or 0) * 0.25,
         "Submit at least one IOC today - a small step gets you back on track."),
        (lambda s: (s.get('prev_ioc_count') or 0) > 0 and (s.get('ioc_count') or 0) < (s.get('prev_ioc_count') or 0) * 0.7,
         "Output dipped a bit - submit one IOC today to get back into rhythm."),
        (lambda s: s.get('active_days') == 1 and (s.get('ioc_count') or 0) > 0,
         "Spreading activity across the week keeps the feed fresh and consistent."),
        # 6-10 Consistency
        (lambda s: (s.get('streak_days') or 0) == 0 and (s.get('ioc_count') or 0) > 0,
         "Small goal: one IOC per day - build a streak and stay in the loop."),
        (lambda s: (s.get('total_days') or 1) > 0 and (s.get('active_days') or 0) / max(s.get('total_days'), 1) < 0.3 and (s.get('ioc_count') or 0) > 0,
         "Try to contribute on one or two more days this week - it will change the picture."),
        (lambda s: (s.get('max_gap_days') or 0) >= 5,
         "After a break - submit one IOC today to get yourself back on track."),
        (lambda s: (s.get('weekend_submissions') or 0) > 0 and (s.get('weekday_submissions') or 0) == 0,
         "Try submitting on a weekday too - daily coverage helps the team."),
        (lambda s: (s.get('ioc_count') or 0) > 0 and (s.get('night_pct') or 0) > 80,
         "Most activity is at night - try a daytime submission to strengthen presence."),
        # 11-16 Type Diversity
        (lambda s: (s.get('distinct_types') or 0) == 1 and (s.get('ioc_count') or 0) >= 3,
         "This week: try another type (Domain, Hash, or URL) - diversify your skills."),
        (lambda s: (s.get('hash_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "Add your first Hash IOC - it opens another angle in investigations."),
        (lambda s: (s.get('domain_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "Try submitting a Domain - DNS analysis will broaden your contribution."),
        (lambda s: (s.get('url_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "One URL from a phishing campaign - a great direction to start."),
        (lambda s: (s.get('email_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "Add an Email IOC - headers and phishing are a good next step."),
        (lambda s: (s.get('ioc_count') or 0) >= 5 and (s.get('ip_count') or 0) / max(s.get('ioc_count'), 1) > 0.8,
         "Strong on IPs - add a Domain or URL this week for variety."),
        # 17-21 Quality
        (lambda s: (s.get('with_comment_pct') or 0) == 0 and (s.get('ioc_count') or 0) > 0,
         "Add a short comment to one IOC today - context helps the whole team."),
        (lambda s: 0 < (s.get('with_comment_pct') or 0) < 30,
         "Pick 2-3 IOCs and add a sentence of context - value goes up quickly."),
        (lambda s: (s.get('avg_comment_len') or 0) > 0 and (s.get('avg_comment_len') or 0) < 10,
         "Expand one comment this week - examples from the team can help."),
        (lambda s: (s.get('with_ticket_pct') or 0) == 0 and (s.get('ioc_count') or 0) > 0,
         "Link one IOC to a ticket - it helps traceability and ownership."),
        (lambda s: 0 < (s.get('with_ticket_pct') or 0) < 40,
         "Small habit: add a ticket ID when you submit - it adds up."),
        # 22-24 Campaign
        (lambda s: (s.get('with_campaign_pct') or 0) == 0 and (s.get('ioc_count') or 0) > 0,
         "Link one IOC to a campaign - it strengthens reports and analysis."),
        (lambda s: 0 < (s.get('with_campaign_pct') or 0) < 20,
         "This week: link 2-3 IOCs to a campaign - see how it affects reports."),
        (lambda s: (s.get('campaigns_created') or 0) == 0 and (s.get('ioc_count') or 0) >= 10,
         "Try creating one campaign for an active investigation - it expands impact."),
        # 25-28 YARA
        (lambda s: (s.get('yara_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "Your first YARA rule - the Playbook's beginner guide can help."),
        (lambda s: (s.get('yara_count') or 0) > 0 and (s.get('avg_yara_quality') or 0) < 20,
         "Share a YARA rule with a peer - it will help you improve quality fast."),
        (lambda s: (s.get('yara_rejected_count') or 0) > 0,
         "Feedback on rejected rules - a chance to sharpen your writing."),
        (lambda s: (s.get('yara_without_ticket') or 0) > 0,
         "Add a ticket reference to your next YARA rule - helps traceability."),
        # 29-32 Feed Hygiene
        (lambda s: (s.get('deletion_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "Spend 10 minutes - filter expired IOCs and keep the feed clean."),
        (lambda s: (s.get('permanent_pct') or 0) == 100 and (s.get('ioc_count') or 0) >= 3,
         "Try a 30-90 day TTL on new IOCs - good practice for feed management."),
        (lambda s: 80 < (s.get('permanent_pct') or 0) < 100,
         "Most IOCs lose relevance over time - a set TTL helps the team."),
        (lambda s: (s.get('stale_iocs_owned') or 0) > 5,
         "Review your older IOCs - update or close them to improve quality."),
        # 33-37 Knowledge
        (lambda s: (s.get('notes_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "Add a note to an existing IOC - it adds knowledge for the whole team."),
        (lambda s: (s.get('with_tags_pct') or 0) == 0 and (s.get('ioc_count') or 0) >= 3,
         "One tag on your next submission - it will ease search and reports."),
        (lambda s: 0 < (s.get('with_tags_pct') or 0) < 20,
         "Tagging habit - even 2-3 tagged IOCs per week make a difference."),
        (lambda s: (s.get('edit_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 5,
         "Pick an old IOC and update or enrich it - review-and-enrich builds the habit."),
        (lambda s: (s.get('rare_find_count') or 0) == 0 and (s.get('ioc_count') or 0) >= 10,
         "Explore less common infrastructure - a new TLD, country, or domain can be a rare find."),
        # 38-42 Growth
        (lambda s: (s.get('active_badges') or 0) == 0 and (s.get('ioc_count') or 0) > 0,
         "One IOC per day for 3 days - and you'll start earning badges."),
        (lambda s: (s.get('lost_badges_count') or 0) > 0,
         "Badges will come back - start a short streak and they'll reappear."),
        (lambda s: (s.get('days_at_current_level') or 0) >= 30,
         "Try a new IOC type or a YARA rule - they can break the level plateau."),
        (lambda s: (s.get('rank_change') or 0) <= -3,
         "Rank dropped - you might be focused on a heavy case. Worth checking priorities."),
        (lambda s: (s.get('total_days') or 1) > 0 and (s.get('days_below_team_avg') or 0) / max(s.get('total_days'), 1) > 0.8,
         "Team average is close - one or two more active days can close the gap."),
        # 43-48 Positive
        (lambda s: 3 <= (s.get('streak_days') or 0) <= 4,
         "Nice streak - one more day and you're On Fire."),
        (lambda s: (s.get('streak_days') or 0) >= 5,
         "You're On Fire - keep one IOC per day to maintain momentum."),
        (lambda s: (s.get('rank_change') or 0) > 0,
         "Rank went up - consistency pays off. Keep going in the same direction."),
        (lambda s: (s.get('active_badges') or 0) >= 3,
         "Solid badges - pick one new challenge this week (type, campaign, or YARA)."),
        (lambda s: (s.get('days_at_current_level') or 999) <= 7 and (s.get('ioc_count') or 0) > 0,
         "You leveled up - set a small goal for the next level (IOCs or YARA)."),
        (lambda s: (s.get('distinct_types') or 0) >= 3 and (s.get('with_campaign_pct') or 0) > 0,
         "Good variety - add comments or tags this week to strengthen quality."),
        # 49-50 Neutral
        (lambda s: (s.get('ioc_count') or 0) < 5 and (s.get('active_days') or 0) <= 2,
         "Your first submission sets the tone - pick one IOC and submit it with short context."),
        (lambda s: True, None),  # fallback: use default (None signals default)
    ]


def get_ambition_message_for_user(user_id, username):
    """
    Return one ambition message for the given analyst (English only).
    Uses same stats as SOC Mentorship for the last 30 days.
    Returns (message_id, message). message_id 0 = default.
    """
    from utils.mentorship import _bulk_analyst_stats, _empty_stats

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    end_dt = now
    start_dt = now - timedelta(days=30)
    prev_end_dt = start_dt - timedelta(days=1)
    prev_start_dt = start_dt - timedelta(days=30)

    all_stats = _bulk_analyst_stats(start_dt, end_dt, prev_start_dt, prev_end_dt)
    analyst_lower = (username or '').strip().lower()
    stats = all_stats.get(analyst_lower)
    if stats is None and user_id is not None:
        for _uname, s in all_stats.items():
            if s.get('user_id') == user_id:
                stats = s
                break
    if stats is None:
        stats = _empty_stats(user_id, username, start_dt, end_dt)
        stats['total_days'] = 30

    rules = _ambition_rules()
    for idx, (cond, msg) in enumerate(rules, 1):
        try:
            if cond(stats):
                return (idx if msg is not None else 0, msg or AMBITION_DEFAULT_MESSAGE)
        except Exception:
            continue
    return (0, AMBITION_DEFAULT_MESSAGE)
