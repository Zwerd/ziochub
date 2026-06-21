"""User inbox notifications (YARA / tag approval outcomes)."""
import json
import logging

from sqlalchemy import func

from extensions import db
from models import User, UserNotification, YaraRule, _utcnow


def resolve_user_id(username: str):
    """Return user id for username (case-insensitive), or None."""
    uname = (username or '').strip()
    if not uname:
        return None
    user = User.query.filter(func.lower(User.username) == uname.lower()).first()
    return user.id if user else None


def tag_suggestion_user_id(item: dict):
    """Resolve user id from a tag suggestion record (prefer stored id)."""
    if not item or not isinstance(item, dict):
        return None
    uid = item.get('suggested_by_user_id')
    if uid is not None:
        try:
            uid = int(uid)
            if uid > 0:
                return uid
        except (TypeError, ValueError):
            pass
    return resolve_user_id(item.get('suggested_by') or '')


def _create_notification(*, user_id, category, outcome, title, body=None, payload=None, dedup_key=None):
    if not user_id:
        return None
    payload_json = json.dumps(payload, ensure_ascii=False) if payload is not None else None
    if dedup_key:
        existing = UserNotification.query.filter_by(user_id=user_id, dedup_key=dedup_key).first()
        if existing:
            existing.category = category
            existing.outcome = outcome
            existing.title = (title or '')[:512]
            existing.body = body
            existing.payload = payload_json
            existing.read_at = None
            existing.created_at = _utcnow()
            return existing
    row = UserNotification(
        user_id=user_id,
        category=category,
        outcome=outcome,
        title=(title or '')[:512],
        body=body,
        payload=payload_json,
        dedup_key=dedup_key,
    )
    db.session.add(row)
    return row


def notify_yara_outcome(user_id, rule, outcome: str, *, reason=None, rejected_by=None):
    """Create inbox notification when a YARA rule is approved or rejected."""
    filename = (rule.filename or '').strip()
    title = filename or 'YARA rule'
    if outcome == 'approved':
        body = 'Your YARA rule was approved and is now active.'
    else:
        reason_text = (reason or '').strip()
        body = reason_text or 'Your YARA rule was rejected by an administrator.'
    payload = {
        'filename': filename,
        'display_name': filename,
        'reason': (reason or '').strip() or None,
        'rejected_by': rejected_by,
    }
    dedup = f'yara:{outcome}:{filename}' if filename else None
    return _create_notification(
        user_id=user_id,
        category='yara',
        outcome=outcome,
        title=title,
        body=body,
        payload=payload,
        dedup_key=dedup,
    )


def notify_ioc_outcome(user_id, row, outcome: str, *, reason=None, ioc_type=None, ioc_value=None, analyst=None):
    """Create inbox notification when a pending IOC is approved or rejected."""
    itype = (ioc_type or getattr(row, 'type', None) or '').strip()
    val = (ioc_value or getattr(row, 'value', None) or '').strip()
    title = f'{itype}: {val[:120]}' if itype and val else (val[:120] or itype or 'IOC')
    if outcome == 'approved':
        body = 'Your IOC was approved and is now distributed to feeds and integrations.'
    else:
        reason_text = (reason or '').strip()
        body = reason_text or 'Your IOC submission was rejected by an administrator.'
    payload = {
        'type': itype,
        'value': val,
        'reason': (reason or '').strip() or None,
    }
    dedup = f'ioc:{outcome}:{itype}:{val.lower()}' if itype and val else None
    return _create_notification(
        user_id=user_id,
        category='ioc',
        outcome=outcome,
        title=title[:512],
        body=body,
        payload=payload,
        dedup_key=dedup,
    )


def notify_tag_outcome(user_id, tag: str, outcome: str):
    """Create inbox notification when a suggested tag is approved or rejected."""
    tag_norm = (tag or '').strip().lower()
    if not tag_norm:
        return None
    title = tag_norm
    if outcome == 'approved':
        body = 'Your tag suggestion was approved and added to the taxonomy.'
    else:
        body = 'Your tag suggestion was not approved.'
    dedup = f'tag:{outcome}:{tag_norm}'
    return _create_notification(
        user_id=user_id,
        category='tag',
        outcome=outcome,
        title=title,
        body=body,
        payload={'tag': tag_norm},
        dedup_key=dedup,
    )


def backfill_yara_rejection_notifications(user_id, username: str):
    """Ensure legacy rejected YARA rows (unseen) have an inbox notification."""
    uname = (username or '').strip().lower()
    if not user_id or not uname:
        return
    try:
        rules = (
            YaraRule.query.filter_by(status='rejected', analyst=uname)
            .filter(YaraRule.rejection_seen_at.is_(None))
            .all()
        )
        for rule in rules:
            notify_yara_outcome(
                user_id,
                rule,
                'rejected',
                reason=rule.rejection_reason,
                rejected_by=rule.rejected_by,
            )
    except Exception:
        logging.exception('backfill_yara_rejection_notifications failed for user_id=%s', user_id)


def notification_to_dict(row: UserNotification) -> dict:
    payload = {}
    if row.payload:
        try:
            payload = json.loads(row.payload)
        except (TypeError, ValueError):
            payload = {}
    return {
        'id': row.id,
        'category': row.category,
        'outcome': row.outcome,
        'title': row.title,
        'body': row.body or '',
        'payload': payload,
        'created_at': row.created_at.isoformat() if row.created_at else None,
        'read': row.read_at is not None,
    }


def dismiss_yara_outcome_notification(user_id, filename, outcome='rejected'):
    """Remove stale inbox item after analyst resubmits a rejected rule."""
    filename = (filename or '').strip()
    if not user_id or not filename:
        return 0
    dedup = f'yara:{outcome}:{filename}'
    row = UserNotification.query.filter_by(user_id=user_id, dedup_key=dedup).first()
    if not row:
        return 0
    db.session.delete(row)
    return 1


def mark_yara_rejection_seen_for_user(user_id, username: str, filename=None):
    """Sync YaraRule.rejection_seen_at when user dismisses yara/rejected inbox items."""
    uname = (username or '').strip().lower()
    if not uname:
        return 0
    now = _utcnow()
    q = YaraRule.query.filter_by(status='rejected', analyst=uname).filter(
        YaraRule.rejection_seen_at.is_(None)
    )
    if filename:
        q = q.filter(func.lower(YaraRule.filename) == filename.strip().lower())
    updated = 0
    for rule in q.all():
        rule.rejection_seen_at = now
        updated += 1
    return updated
