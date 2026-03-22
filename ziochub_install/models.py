"""
SQLAlchemy models for ZIoCHub. Uses db from extensions (no app import).
"""
from datetime import datetime, timezone
from sqlalchemy import UniqueConstraint, Index

from extensions import db

try:
    from flask_login import UserMixin
except ImportError:
    UserMixin = object


def _utcnow():
    """Return current UTC time as a naive datetime (drop tzinfo for SQLite compat)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    dir = db.Column(db.String(8), nullable=True, default='ltr')  # ltr | rtl
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # user who created
    created_at = db.Column(db.DateTime, default=_utcnow)
    iocs = db.relationship('IOC', backref='campaign', lazy=True, foreign_keys='IOC.campaign_id')


class User(UserMixin, db.Model):
    """Authentication: local or LDAP users."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)  # NULL for LDAP
    source = db.Column(db.String(50), nullable=False, default='local')  # local | ldap
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)


class SystemSetting(db.Model):
    """Key-value storage for auth config (LDAP, AUTH_MODE, etc.). Phase 2.5."""
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)


class UserProfile(db.Model):
    """User display info: avatar, role description, preferences."""
    __tablename__ = 'user_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    display_name = db.Column(db.String(255), nullable=True)
    role_description = db.Column(db.Text, nullable=True)
    avatar_path = db.Column(db.String(512), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    mute_sound = db.Column(db.Boolean, default=False, nullable=False)
    ambition_popup_disabled = db.Column(db.Boolean, default=False, nullable=False)
    achievement_popup_disabled = db.Column(db.Boolean, default=False, nullable=False)


class UserSession(db.Model):
    """Session tracking for analytics."""
    __tablename__ = 'user_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_at = db.Column(db.DateTime, default=_utcnow)
    logout_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)


class IOC(db.Model):
    __tablename__ = 'iocs'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(1024), nullable=False)
    analyst = db.Column(db.String(255), nullable=False)
    ticket_id = db.Column(db.String(255), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    expiration_date = db.Column(db.DateTime, nullable=True)  # NULL = Permanent
    created_at = db.Column(db.DateTime, default=_utcnow)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # FK to users; NULL = legacy
    tags = db.Column(db.Text, nullable=True, default='[]')  # JSON array of strings
    submission_method = db.Column(db.String(16), nullable=True, default='single')  # single | csv | txt | paste | import (nullable for pre-migration rows)
    # Rare Find: first-ever in system (for badge)
    country_code = db.Column(db.String(8), nullable=True)   # GEO for IP (ISO 2-letter)
    tld = db.Column(db.String(32), nullable=True)            # TLD for Domain/URL (e.g. com, org)
    email_domain = db.Column(db.String(255), nullable=True) # domain part for Email (e.g. evil.com)
    rare_find_type = db.Column(db.String(32), nullable=True) # 'country' | 'tld' | 'email_domain' when first-ever
    __table_args__ = (
        UniqueConstraint('type', 'value', name='u_type_value'),
        Index('ix_iocs_created_at', 'created_at'),
        Index('ix_iocs_expiration_date', 'expiration_date'),
        Index('ix_iocs_campaign_id', 'campaign_id'),
        Index('ix_iocs_analyst', 'analyst'),
    )


class IocHistory(db.Model):
    """Audit log per IOC (type+value): created, deleted. Survives IOC deletion so re-add shows full timeline."""
    __tablename__ = 'ioc_history'
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(50), nullable=False)
    ioc_value = db.Column(db.String(1024), nullable=False)
    event_type = db.Column(db.String(32), nullable=False)  # 'created' | 'edited' | 'deleted' | 'expired'
    username = db.Column(db.String(255), nullable=True)
    at = db.Column(db.DateTime, default=_utcnow, nullable=False)
    payload = db.Column(db.Text, nullable=True)  # JSON: e.g. {"expiration_date": "...", "comment": "..."}
    __table_args__ = (
        Index('ix_ioc_history_at', 'at'),
        Index('ix_ioc_history_at_event_type', 'at', 'event_type'),
        Index('ix_ioc_history_type_value', 'ioc_type', 'ioc_value'),
    )


class IocNote(db.Model):
    """Analyst notes / knowledge sharing on specific IOCs. Keyed by type+value so notes survive deletion cycles."""
    __tablename__ = 'ioc_notes'
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(50), nullable=False)
    ioc_value = db.Column(db.String(1024), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)
    __table_args__ = (Index('ix_ioc_notes_type_value', 'ioc_type', 'ioc_value'),)


class SanityExclusion(db.Model):
    """Analyst-excluded sanity check anomalies. Excluded items won't show again in Feed Pulse."""
    __tablename__ = 'sanity_exclusions'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(1024), nullable=False)
    ioc_type = db.Column(db.String(50), nullable=False)
    anomaly_type = db.Column(db.String(80), nullable=False)
    excluded_by = db.Column(db.String(255), nullable=True)
    excluded_at = db.Column(db.DateTime, default=_utcnow)
    __table_args__ = (UniqueConstraint('value', 'ioc_type', 'anomaly_type', name='u_sanity_excl_key'),)


class YaraRule(db.Model):
    __tablename__ = 'yara_rules'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True, nullable=False)
    analyst = db.Column(db.String(255), nullable=False)
    ticket_id = db.Column(db.String(255), nullable=True)
    comment = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=_utcnow)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=True)
    quality_points = db.Column(db.Integer, nullable=True)  # Champs: 10-50 by rule quality
    status = db.Column(db.String(32), nullable=False, default='approved')  # pending | approved | rejected
    __table_args__ = (Index('ix_yara_rules_uploaded_at', 'uploaded_at'), Index('ix_yara_rules_uploaded_at_status', 'uploaded_at', 'status'),)


# --- Champs Analysis 5.0 (Operational Hall of Fame) ---


class TeamGoal(db.Model):
    """Team-wide goal (weekly/monthly) for Team HUD progress bar."""
    __tablename__ = 'team_goals'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(512), nullable=False)
    description = db.Column(db.Text, nullable=True)  # optional; shown as tooltip on hover over title
    target_value = db.Column(db.Integer, nullable=False)
    current_value = db.Column(db.Integer, default=0, nullable=False)
    unit = db.Column(db.String(64), nullable=True)  # e.g. "IOCs", "YARA rules"
    goal_type = db.Column(db.String(32), nullable=False, default='ioc_add')  # ioc_add | yara_add | deletion
    period = db.Column(db.String(32), nullable=False, default='weekly')  # weekly | monthly
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)


class ActivityEvent(db.Model):
    """Event log for News Ticker (submit, rank change, goal progress)."""
    __tablename__ = 'activity_events'
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)  # ioc_submit, yara_upload, rank_change, goal_progress, deletion
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    payload = db.Column(db.Text, nullable=True)  # JSON
    created_at = db.Column(db.DateTime, default=_utcnow)
    __table_args__ = (Index('ix_activity_events_created_at', 'created_at'), Index('ix_activity_events_event_type', 'event_type'),)


class ChampRankSnapshot(db.Model):
    """Daily rank snapshot for trend calculation (▲/▼)."""
    __tablename__ = 'champ_rank_snapshots'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rank = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    snapshot_date = db.Column(db.Date, nullable=False)  # date only for daily comparison
    __table_args__ = (UniqueConstraint('user_id', 'snapshot_date', name='u_champ_snapshot_user_date'),)


class ChampScore(db.Model):
    """Materialized per-user Champs score (efficient leaderboard for 1M+ IOCs). Updated on IOC/YARA add/delete."""
    __tablename__ = 'champ_scores'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    score = db.Column(db.Integer, nullable=False, default=0)
    total_iocs = db.Column(db.Integer, nullable=False, default=0)
    yara_count = db.Column(db.Integer, nullable=False, default=0)
    deletion_count = db.Column(db.Integer, nullable=False, default=0)
    streak_days = db.Column(db.Integer, nullable=False, default=0)
    last_activity = db.Column(db.Date, nullable=True)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)
