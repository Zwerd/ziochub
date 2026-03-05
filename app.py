"""
ThreatGate - IOC & YARA Management (SQLite backend).

MIGRATION: Before first run with SQLite, manually backup your data/ folder:
    - Copy the entire data/ directory (e.g. data/ -> data_backup_YYYYMMDD/)
    - Migration runs once on startup when the DB is empty and imports from data/Main/*.txt and data/Main/yara.txt
"""
import json
import os

import logging
import logging.handlers
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError, OperationalError

from constants import DEFAULT_IOC_LIMIT, DEFAULT_PAGE_SIZE, IOC_FILES, VERSION
from extensions import db

try:
    import config as _config
except ImportError:
    _config = None

# Try to import geoip2, but don't fail if not available
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Directory paths - must be defined before app (data/ is SMB share, holds DB and IOC data)
_base_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = (_config and _config.DATA_DIR) or os.path.join(_base_dir, 'data')
# Resolve data/Main so it works on case-sensitive FS (e.g. "Main" vs "main")
_main_candidate = os.path.join(_data_dir, 'Main')
if os.path.isdir(_main_candidate):
    DATA_MAIN = _main_candidate
else:
    for name in (os.listdir(_data_dir) if os.path.isdir(_data_dir) else []):
        if name.lower() == 'main':
            DATA_MAIN = os.path.join(_data_dir, name)
            break
    else:
        DATA_MAIN = _main_candidate  # use default and create below
DATA_YARA = os.path.join(_data_dir, 'YARA')
DATA_YARA_PENDING = os.path.join(_data_dir, 'YARA_pending')
ALLOWLIST_FILE = os.path.join(_data_dir, 'allowlist.txt')
PLAYBOOK_CUSTOM_FILE = os.path.join(_data_dir, 'playbook_custom.json')
SSL_DIR = os.path.join(_data_dir, 'ssl')
SSL_CERT_FILE = os.path.join(SSL_DIR, 'cert.pem')
SSL_KEY_FILE = os.path.join(SSL_DIR, 'key.pem')
SSL_CA_FILE = os.path.join(SSL_DIR, 'ca.pem')
GEOIP_DB_PATH = os.path.join(_data_dir, 'GeoLite2-City.mmdb')
os.makedirs(DATA_MAIN, exist_ok=True)
os.makedirs(DATA_YARA, exist_ok=True)
os.makedirs(DATA_YARA_PENDING, exist_ok=True)
os.makedirs(SSL_DIR, exist_ok=True)

app = Flask(__name__)


def _get_secret_key():
    """Return a stable SECRET_KEY shared across all Gunicorn workers.

    Priority: config.py → SECRET_KEY env var → persistent file on disk.
    A random key is generated once and saved so every worker (and every
    restart) uses the same value.
    """
    key = (_config and _config.SECRET_KEY) or os.environ.get('SECRET_KEY')
    if key:
        return key
    key_file = os.path.join(_data_dir, '.secret_key')
    try:
        with open(key_file, 'r') as f:
            stored = f.read().strip()
        if stored:
            return stored
    except FileNotFoundError:
        pass
    new_key = os.urandom(32).hex()
    os.makedirs(_data_dir, exist_ok=True)
    with open(key_file, 'w') as f:
        f.write(new_key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return new_key


app.config['SECRET_KEY'] = _get_secret_key()
app.config['MAX_CONTENT_LENGTH'] = (_config and getattr(_config, 'MAX_CONTENT_LENGTH', None)) or 16 * 1024 * 1024
_db_path = (_config and getattr(_config, 'DB_PATH', None)) or os.path.join(_data_dir, 'threatgate.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + _db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DATA_YARA'] = DATA_YARA
app.config['DATA_YARA_PENDING'] = DATA_YARA_PENDING
db.init_app(app)

# --- Blueprints ---
from routes.feeds import bp as feeds_bp
from routes.admin import bp as admin_bp, pages_bp as admin_pages_bp
from routes.yara import bp as yara_bp
from routes.campaigns import bp as campaigns_bp
from routes.champs import bp as champs_bp
from routes.auth import bp as auth_bp
from routes.search import bp as search_bp
from routes.stats import stats_bp
from routes.ioc import bp as ioc_bp
from routes.reports import reports_bp
app.register_blueprint(feeds_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(admin_pages_bp)
app.register_blueprint(yara_bp)
app.register_blueprint(campaigns_bp)
app.register_blueprint(champs_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(search_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(ioc_bp)
app.register_blueprint(reports_bp)

# --- Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) if user_id else None


@app.context_processor
def _inject_auth_context():
    """Inject profile, display_name, avatar_url, version into all templates (for base_app, admin, etc.)."""
    ctx = {'version': VERSION}
    if not current_user.is_authenticated:
        ctx.update({'profile': None, 'display_name': None, 'avatar_url': None})
    else:
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        display_name = (profile and profile.display_name) or current_user.username
        avatar_url = url_for('static', filename=profile.avatar_path) if profile and profile.avatar_path else None
        ctx.update({'profile': profile, 'display_name': display_name, 'avatar_url': avatar_url})
    return ctx


_CHANGE_PW_ALLOWED = frozenset(('/change-password', '/logout', '/static'))

@app.before_request
def _enforce_password_change():
    """Block all navigation for users that must change their password."""
    if (current_user.is_authenticated
            and getattr(current_user, 'must_change_password', False)
            and not any(request.path.startswith(p) for p in _CHANGE_PW_ALLOWED)):
        # API calls expect JSON; redirect would cause "Unexpected token '<'" when parsing response
        if request.path.startswith('/api/'):
            return jsonify({'success': False, 'message': 'Password change required', 'require_password_change': True}), 403
        return redirect(url_for('auth.change_password'))


# --- Audit Logger: CEF format, local 48h rotation, optional UDP syslog ---
# Initialized lazily in audit_log (needs _get_setting)
_cef_logger_inited = False


def get_audit_log_path():
    """Return path to CEF audit log file (for admin log viewer)."""
    return os.path.join(_data_dir, 'audit_cef.log')


def _api_error(message: str, status: int = 500):
    """Return a consistent JSON error response. Use for API endpoints."""
    return jsonify({'success': False, 'message': message}), status


def _api_ok(data=None, message=None):
    """Return a consistent JSON success response (status 200). Use for API endpoints."""
    body = {'success': True}
    if message is not None:
        body['message'] = message
    if data is not None and isinstance(data, dict):
        body.update(data)
    return jsonify(body), 200


def _commit_with_retry(max_attempts=3):
    """Commit the current session; retry on SQLite 'database is locked' (offline-safe)."""
    for attempt in range(max_attempts):
        try:
            db.session.commit()
            return
        except OperationalError as e:
            err = str(e).lower()
            if 'locked' not in err and 'busy' not in err:
                raise
            db.session.rollback()
            if attempt + 1 == max_attempts:
                raise
            time.sleep(0.05 * (attempt + 1))

def audit_log(action: str, detail: str = ''):
    """Write CEF-formatted audit log (local 48h rotation + optional UDP syslog)."""
    global _cef_logger_inited
    client_ip = request.remote_addr if request else '-'
    user_id = None
    username = None
    try:
        if current_user.is_authenticated:
            user_id = current_user.id
            username = current_user.username
    except Exception:
        pass
    try:
        if not _cef_logger_inited:
            from utils.cef_logger import init_cef_logger
            udp_enabled = _get_setting('syslog_udp_enabled', 'false').lower() == 'true'
            udp_host = _get_setting('syslog_udp_host', '').strip() if udp_enabled else ''
            udp_port = int(_get_setting('syslog_udp_port', '514') or '514')
            init_cef_logger(
                os.path.join(_data_dir, 'audit_cef.log'),
                udp_host,
                udp_port,
            )
            _cef_logger_inited = True
        from utils.cef_logger import cef_log
        cef_log(action=action, detail=detail, client_ip=client_ip, user_id=user_id, username=username)
    except Exception:
        logging.exception('audit_log failed')


def _log_champs_event(event_type, user_id=None, payload=None):
    """Log activity event for Champs ticker and scoring."""
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


def _log_ioc_history(ioc_type: str, ioc_value: str, event_type: str, username: str = None, payload: dict = None):
    """Append one event to ioc_history (created/deleted). Caller must commit after."""
    try:
        uname = (username or '').strip() or None
        payload_json = json.dumps(payload) if payload else None
        db.session.add(IocHistory(
            ioc_type=ioc_type,
            ioc_value=ioc_value.strip(),
            event_type=event_type,
            username=uname,
            payload=payload_json,
        ))
    except Exception:
        logging.exception('_log_ioc_history failed')


# Load GeoIP database if available
geoip_reader = None
if GEOIP_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
    try:
        geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception:
        geoip_reader = None

# IOC_FILES from constants; FILE_YARA for legacy
FILE_YARA = os.path.join(DATA_MAIN, 'yara.txt')


def _resolve_analyst_to_user(analyst_or_id):
    """Resolve analyst (username str or user_id int) to (user_id, username). Returns None if not found or inactive."""
    if analyst_or_id is None:
        return None
    if isinstance(analyst_or_id, str):
        s = analyst_or_id.strip()
        if not s:
            return None
        if s.isdigit():
            u = db.session.get(User, int(s))
            return (u.id, u.username.lower()) if u and getattr(u, 'is_active', True) else None
        u = User.query.filter(func.lower(User.username) == s.lower()).first()
        return (u.id, u.username.lower()) if u and getattr(u, 'is_active', True) else None
    if isinstance(analyst_or_id, int):
        u = db.session.get(User, analyst_or_id)
        return (u.id, u.username.lower()) if u and getattr(u, 'is_active', True) else None
    return None


from models import (
    Campaign, IOC, IocHistory, IocNote, YaraRule, SanityExclusion,
    User, UserProfile, UserSession, SystemSetting,
    TeamGoal, ActivityEvent, ChampRankSnapshot,
    _utcnow,
)


def get_ioc_filepath(ioc_type):
    """Single source of truth for IOC file paths. Used by write_ioc_to_file, get_stats, and all other readers/writers."""
    filename = IOC_FILES.get(ioc_type)
    if not filename:
        return None
    return os.path.join(DATA_MAIN, filename)

from utils.validation import (
    AUTO_DETECT_PATTERNS,
    PRIORITY_ORDER,
    REGEX_PATTERNS,
    validate_ioc,
    detect_ioc_type,
)
from utils.refanger import refanger, sanitize_comment
from utils.ioc_decode import prepare_text_for_ioc_extraction
from utils.allowlist import load_allowlist, check_allowlist as _check_allowlist
from utils.yara_utils import yara_safe_path
from utils.validation_warnings import get_ioc_warnings
from utils.validation_messages import (
    MSG_MISSING_FIELDS,
    MSG_MISSING_FIELDS_TYPE_VALUE,
    MSG_INVALID_IOC_TYPE,
    MSG_IOC_EXISTS,
    MSG_INVALID_FILENAME,
    MSG_FILENAME_REQUIRED,
    MSG_FILE_NOT_FOUND,
)
from utils.sanity_checks import (
    check_critical as check_sanity_critical,
    get_sanity_warnings,
    get_feed_pulse_anomalies,
)
from utils.auth import hash_password, verify_password
from utils.decorators import login_required, admin_required
from utils.ldap_auth import try_ldap_bind, try_ldap_mock_dev, check_ldap_reachable, is_dev_mode
from utils.champs import (
    compute_analyst_scores,
    compute_yara_quality_points,
    compute_ioc_points,
    get_rank_trend,
    get_rank_change_events,
    save_daily_rank_snapshots,
    compute_team_goal_current,
    compute_team_goal_for_week,
    get_analyst_detail,
    _week_start,
    _get_badges,
    _get_level_and_xp,
    _to_date,
    YARA_DEFAULT, YARA_MIN, YARA_MAX, DELETION,
)


BADGE_META = {
    'on_fire':         {'emoji': '🔥', 'label': 'On Fire',         'description': '5-day submission streak'},
    'warm_streak':     {'emoji': '🌡️', 'label': 'Warm Streak',     'description': '3-4 day streak'},
    'night_owl':       {'emoji': '🦉', 'label': 'Night Owl',       'description': 'Activity between 22:00-04:00'},
    'early_bird':      {'emoji': '🌞', 'label': 'Early Bird',      'description': 'Activity between 05:00-07:00'},
    'weekend_warrior': {'emoji': '🗓️', 'label': 'Weekend Warrior', 'description': 'Activity on Friday or Saturday'},
    'rare_find':       {'emoji': '💎', 'label': 'Rare Find',       'description': 'First-ever in system: new country, TLD, or email domain'},
    'dedicated':       {'emoji': '💪', 'label': 'Dedicated',       'description': '30+ IOCs total'},
    'veteran':         {'emoji': '🎖️', 'label': 'Veteran',         'description': '80+ IOCs total'},
    'clean_slate':     {'emoji': '✨', 'label': 'Clean Slate',     'description': 'Removed at least one expired IOC'},
    'janitor':         {'emoji': '🧹', 'label': 'Janitor',         'description': '5+ expired IOCs removed'},
    'cleanup_crew':    {'emoji': '🧼', 'label': 'Cleanup Crew',    'description': '15+ expired IOCs removed'},
    'team_player':     {'emoji': '🤝', 'label': 'Team Player',     'description': 'At least one IOC linked to a campaign'},
    'campaign_master': {'emoji': '🎯', 'label': 'Campaign Master', 'description': '10+ IOCs linked to campaigns'},
    'yara_rookie':     {'emoji': '📜', 'label': 'YARA Rookie',     'description': 'Uploaded at least one YARA rule'},
    'yara_master':     {'emoji': '👑', 'label': 'YARA Master',     'description': '3+ YARA rules'},
    'yara_legend':     {'emoji': '🏆', 'label': 'YARA Legend',     'description': '8+ YARA rules'},
    'hash_hunter':     {'emoji': '🔐', 'label': 'Hash Hunter',     'description': '10+ hashes'},
    'domain_scout':    {'emoji': '🌐', 'label': 'Domain Scout',    'description': '15+ domains'},
    'ip_tracker':      {'emoji': '📍', 'label': 'IP Tracker',      'description': '25+ IPs'},
    'url_surfer':      {'emoji': '🏄', 'label': 'URL Surfer',      'description': '10+ URLs'},
    'phish_buster':    {'emoji': '🎣', 'label': 'Phish Buster',    'description': '5+ emails'},
    'triple_threat':   {'emoji': '🎪', 'label': 'Triple Threat',   'description': 'Submitted at least 3 IOC types'},
    'all_rounder':     {'emoji': '🌟', 'label': 'All-Rounder',     'description': 'Submitted all 5 IOC types'},
    'consistent':      {'emoji': '📅', 'label': 'Consistent',      'description': 'Activity on 7+ different days'},
    'ever_present':    {'emoji': '⚡', 'label': 'Ever Present',    'description': 'Activity on 15+ different days'},
}


def _compute_user_badges(user_id, username, scoring_method=None):
    """Compute current badge keys for a user. Lightweight wrapper around _get_badges."""
    if scoring_method is None:
        scoring_method = _get_setting('champs_scoring_method', '1')
    analyst_lower = (username or '').lower()
    analyst_daily = defaultdict(int)
    ioc_rows = db.session.query(IOC.created_at, IOC.type, IOC.campaign_id).filter(
        func.lower(IOC.analyst) == analyst_lower
    ).all()
    for created_at, ioc_type, campaign_id in ioc_rows:
        d = _to_date(created_at)
        if d:
            analyst_daily[d] = analyst_daily.get(d, 0) + compute_ioc_points(ioc_type, campaign_id)
    yara_rows = db.session.query(YaraRule.uploaded_at, YaraRule.quality_points).filter(
        func.lower(YaraRule.analyst) == analyst_lower
    ).all()
    for (uploaded_at, qp) in yara_rows:
        d = _to_date(uploaded_at)
        if d:
            pts = max(YARA_MIN, min(YARA_MAX, qp if qp is not None else YARA_DEFAULT))
            analyst_daily[d] = analyst_daily.get(d, 0) + pts
    analyst_deletions = {analyst_lower: 0}
    if user_id:
        del_rows = db.session.query(ActivityEvent.payload).filter(
            ActivityEvent.event_type == 'ioc_deletion', ActivityEvent.user_id == user_id
        ).all()
        for (payload,) in del_rows:
            try:
                if json.loads(payload or '{}').get('was_expired'):
                    analyst_deletions[analyst_lower] += 1
            except (json.JSONDecodeError, TypeError):
                pass
    return set(_get_badges(db, IOC, YaraRule, ActivityEvent, analyst_lower, user_id,
                           {analyst_lower: dict(analyst_daily)}, analyst_deletions,
                           scoring_method=scoring_method))


def _detect_new_badges(old_badges, new_badges):
    """Return list of badge detail dicts for newly earned badges."""
    earned = new_badges - old_badges
    if not earned:
        return []
    return [{'key': k, **BADGE_META.get(k, {'emoji': '🏅', 'label': k, 'description': ''})} for k in earned]


def _capture_champs_before(user_id, username):
    """Snapshot badges, level, and rank before IOC submission."""
    scoring_method = _get_setting('champs_scoring_method', '1')
    badges = _compute_user_badges(user_id, username, scoring_method)
    rows = compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent, scoring_method=scoring_method)
    analyst_lower = (username or '').lower()
    score, rank = 0, 0
    for r in rows:
        if r.get('user_id') == user_id or r['analyst'] == analyst_lower:
            score = r['score']
            rank = r['rank']
            break
    level = _get_level_and_xp(score)[0]
    return {'badges': badges, 'level': level, 'rank': rank, 'score': score, 'scoring_method': scoring_method}


def _detect_champs_changes(before, user_id, username):
    """Compare champs state after IOC submission and return dict with achievement fields."""
    sm = before['scoring_method']
    after_badges = _compute_user_badges(user_id, username, sm)
    rows = compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent, scoring_method=sm)
    analyst_lower = (username or '').lower()
    score, rank = 0, 0
    for r in rows:
        if r.get('user_id') == user_id or r['analyst'] == analyst_lower:
            score = r['score']
            rank = r['rank']
            break
    level = _get_level_and_xp(score)[0]
    result = {}
    new_badges = _detect_new_badges(before['badges'], after_badges)
    if new_badges:
        result['new_badges'] = new_badges
    if level > before['level']:
        result['level_up'] = {'old_level': before['level'], 'new_level': level}
    if 0 < rank < before['rank']:
        result['rank_up'] = {'old_rank': before['rank'], 'new_rank': rank}
    return result


def _auto_ticket_id(user_id):
    """Generate ticket ID in format XY-YYYYMMDD-HHMM from user's display name initials + current timestamp."""
    initials = 'XX'
    if user_id:
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        name = (profile.display_name if profile and profile.display_name else None)
        if not name:
            user = User.query.get(user_id)
            name = user.username if user else None
        if name:
            parts = name.strip().split()
            if len(parts) >= 2:
                initials = (parts[0][0] + parts[1][0]).upper()
            elif len(parts) == 1 and len(parts[0]) >= 2:
                initials = parts[0][:2].upper()
            elif len(parts) == 1:
                initials = (parts[0][0] * 2).upper()
    now = datetime.now()
    return f"{initials}-{now.strftime('%Y%m%d')}-{now.strftime('%H%M')}"


def check_allowlist(value, ioc_type):
    """Check allowlist using ALLOWLIST_FILE."""
    return _check_allowlist(value, ioc_type, ALLOWLIST_FILE)


def get_country_code(ip_address):
    """Get country code (lowercase ISO 2-letter) for an IP address using GeoIP."""
    if not geoip_reader:
        return None
    
    try:
        response = geoip_reader.city(ip_address)
        country_code = response.country.iso_code
        if country_code:
            # Return lowercase 2-letter ISO code for flag-icons CSS
            return country_code.lower()
    except Exception:
        pass
    
    return None


def calculate_expiration_date(ttl):
    """Calculate expiration date based on TTL selection. Returns datetime or None (Permanent)."""
    if ttl == 'Permanent':
        return None
    today = datetime.now()
    ttl_map = {
        '1 Week': timedelta(weeks=1),
        '1 Month': timedelta(days=30),
        '3 Months': timedelta(days=90),
        '1 Year': timedelta(days=365)
    }
    if ttl in ttl_map:
        return today + ttl_map[ttl]
    return None


def check_ioc_exists(ioc_type, value):
    """Check if an IOC already exists in DB (case-insensitive)."""
    return IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.strip().lower()).first() is not None


def _compute_rare_find_fields(ioc_type, value):
    """
    Compute country_code, tld, email_domain and rare_find_type for Rare Find badge.
    Returns dict: country_code, tld, email_domain, rare_find_type (one of 'country'|'tld'|'email_domain' or None).
    """
    out = {'country_code': None, 'tld': None, 'email_domain': None, 'rare_find_type': None}
    val = (value or '').strip()
    if not val:
        return out
    if ioc_type == 'IP':
        cc = get_country_code(val)
        if cc:
            out['country_code'] = cc
            if IOC.query.filter(IOC.country_code == cc).count() == 0:
                out['rare_find_type'] = 'country'
    elif ioc_type == 'Domain':
        if '.' in val:
            tld = val.split('.')[-1].lower()
            if tld and len(tld) <= 30:
                out['tld'] = tld
                if IOC.query.filter(IOC.tld == tld).count() == 0:
                    out['rare_find_type'] = 'tld'
    elif ioc_type == 'URL':
        try:
            host = urlparse(val).hostname
            if host and '.' in host:
                tld = host.split('.')[-1].lower()
                if tld and len(tld) <= 30:
                    out['tld'] = tld
                    if IOC.query.filter(IOC.tld == tld).count() == 0:
                        out['rare_find_type'] = 'tld'
        except Exception:
            pass
    elif ioc_type == 'Email':
        if '@' in val:
            domain = val.split('@')[-1].lower()
            if domain and len(domain) <= 250:
                out['email_domain'] = domain
                if IOC.query.filter(IOC.email_domain == domain).count() == 0:
                    out['rare_find_type'] = 'email_domain'
    return out


def _create_ioc(ioc_type, value, analyst, submission_method='single', *,
                 ticket_id=None, comment=None, expiration_date=None,
                 campaign_id=None, user_id=None, tags=None, created_at=None,
                 rare=None):
    """
    Build an IOC model instance with all standard fields.
    `rare` should be a dict from _compute_rare_find_fields or None.
    """
    r = rare or {}
    kwargs = dict(
        type=ioc_type,
        value=value.strip() if value else value,
        analyst=analyst,
        ticket_id=ticket_id or None,
        comment=comment or None,
        expiration_date=expiration_date,
        campaign_id=campaign_id,
        user_id=user_id,
        submission_method=submission_method,
        country_code=r.get('country_code'),
        tld=r.get('tld'),
        email_domain=r.get('email_domain'),
        rare_find_type=r.get('rare_find_type'),
    )
    if tags is not None:
        kwargs['tags'] = tags
    if created_at is not None:
        kwargs['created_at'] = created_at
    return IOC(**kwargs)


def _get_setting(key: str, default: str = '') -> str:
    """Get system setting by key. Returns default if table missing or DB error."""
    try:
        s = SystemSetting.query.filter_by(key=key).first()
        return (s.value or default) if s else default
    except OperationalError:
        try:
            _ensure_system_settings_table()
            s = SystemSetting.query.filter_by(key=key).first()
            return (s.value or default) if s else default
        except Exception:
            return default


def _set_setting(key: str, value: str) -> None:
    """Set system setting. No-op if table missing or DB error."""
    try:
        s = SystemSetting.query.filter_by(key=key).first()
        if s:
            s.value = value
        else:
            db.session.add(SystemSetting(key=key, value=value))
        _commit_with_retry()
    except OperationalError:
        try:
            _ensure_system_settings_table()
            s = SystemSetting.query.filter_by(key=key).first()
            if s:
                s.value = value
            else:
                db.session.add(SystemSetting(key=key, value=value))
            _commit_with_retry()
        except Exception:
            pass


def _certificate_status():
    """Return dict: cert_present, key_present, ca_present, expiry_iso, expiry_message, error."""
    out = {'cert_present': False, 'key_present': False, 'ca_present': False, 'expiry_iso': None, 'expiry_message': None, 'error': None}
    out['cert_present'] = os.path.isfile(SSL_CERT_FILE)
    out['key_present'] = os.path.isfile(SSL_KEY_FILE)
    out['ca_present'] = os.path.isfile(SSL_CA_FILE)
    if not out['cert_present']:
        return out
    try:
        import subprocess
        r = subprocess.run(
            ['openssl', 'x509', '-enddate', '-noout', '-in', SSL_CERT_FILE],
            capture_output=True, text=True, timeout=5, cwd=_base_dir
        )
        if r.returncode == 0 and r.stdout.strip().startswith('notAfter='):
            # notAfter=Dec 31 23:59:59 2025 GMT
            out['expiry_iso'] = r.stdout.strip().replace('notAfter=', '').strip()
            out['expiry_message'] = out['expiry_iso']
    except Exception as e:
        out['error'] = str(e)
    return out


@app.route('/')
def index():
    """Render the main page."""
    authenticated = current_user.is_authenticated
    is_admin = authenticated and current_user.is_admin
    profile = None
    display_name = None
    avatar_url = None
    if authenticated:
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        display_name = (profile and profile.display_name) or current_user.username
        if profile and profile.avatar_path:
            avatar_url = url_for('static', filename=profile.avatar_path)
    return render_template(
        'index.html',
        authenticated=authenticated,
        is_admin=is_admin,
        display_name=display_name,
        avatar_url=avatar_url,
    )


@app.route('/favicon.ico')
def favicon():
    """Redirect browser favicon request to static ICO."""
    return redirect(url_for('static', filename='favicon.ico'))


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring and load balancer health checks.
    Returns system status including database connectivity and feed operational status.
    """
    health_status = {
        'status': 'healthy',
        'timestamp': _utcnow().isoformat(),
        'version': '5.3',
        'checks': {}
    }
    
    # Check database connectivity
    try:
        db.session.execute(text('SELECT 1'))
        health_status['checks']['database'] = {
            'status': 'connected',
            'path': _db_path
        }
    except Exception as e:
        health_status['status'] = 'unhealthy'
        health_status['checks']['database'] = {
            'status': 'error',
            'error': str(e)
        }
    
    # Check database tables exist
    try:
        tables = db.session.execute(text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('iocs', 'campaigns', 'yara_rules')"
        )).fetchall()
        table_names = [row[0] for row in tables]
        health_status['checks']['database']['tables'] = table_names
        if len(table_names) < 3:
            health_status['status'] = 'degraded'
            health_status['checks']['database']['warning'] = 'Some tables missing'
    except Exception as e:
        health_status['checks']['database']['tables_error'] = str(e)
    
    # Check data directory accessibility
    try:
        if os.path.exists(_data_dir) and os.access(_data_dir, os.W_OK):
            health_status['checks']['data_directory'] = {
                'status': 'accessible',
                'path': _data_dir
            }
        else:
            health_status['status'] = 'unhealthy'
            health_status['checks']['data_directory'] = {
                'status': 'error',
                'error': 'Data directory not accessible'
            }
    except Exception as e:
        health_status['status'] = 'unhealthy'
        health_status['checks']['data_directory'] = {
            'status': 'error',
            'error': str(e)
        }
    
    # Check feed generation (test one feed endpoint)
    try:
        now = datetime.now()
        test_count = IOC.query.filter(
            db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
        ).count()
        health_status['checks']['feeds'] = {
            'status': 'operational',
            'active_iocs': test_count
        }
    except Exception as e:
        health_status['status'] = 'unhealthy'
        health_status['checks']['feeds'] = {
            'status': 'error',
            'error': str(e)
        }
    
    # Check GeoIP database (optional)
    if GEOIP_AVAILABLE:
        try:
            if os.path.exists(GEOIP_DB_PATH):
                health_status['checks']['geoip'] = {
                    'status': 'available',
                    'path': GEOIP_DB_PATH
                }
            else:
                health_status['checks']['geoip'] = {
                    'status': 'not_found',
                    'note': 'GeoIP is optional, system works without it'
                }
        except Exception as e:
            health_status['checks']['geoip'] = {
                'status': 'error',
                'error': str(e)
            }
    else:
        health_status['checks']['geoip'] = {
            'status': 'not_installed',
            'note': 'GeoIP is optional'
        }

    # LDAP health (Phase 3.7)
    try:
        ldap_enabled = _get_setting('ldap_enabled', 'false').lower() == 'true'
        if ldap_enabled:
            reachable, msg = check_ldap_reachable(
                _get_setting('ldap_url', ''),
                _get_setting('ldap_base_dn', ''),
                _get_setting('ldap_bind_dn', ''),
                _get_setting('ldap_bind_password', ''),
            )
            health_status['checks']['ldap'] = {
                'status': 'reachable' if reachable else 'unreachable',
                'message': msg,
            }
        else:
            health_status['checks']['ldap'] = {
                'status': 'disabled',
                'message': 'LDAP not enabled',
            }
    except Exception as e:
        health_status['checks']['ldap'] = {
            'status': 'error',
            'error': str(e)[:100],
        }
    
    # Determine HTTP status code
    if health_status['status'] == 'healthy':
        status_code = 200
    elif health_status['status'] == 'degraded':
        status_code = 200  # Still return 200 but indicate degraded status
    else:
        status_code = 503  # Service Unavailable
    
    return jsonify(health_status), status_code


def check_expiration_status(exp_date_str):
    """Check expiration status. Malformed dates default to Permanent/Active."""
    if not exp_date_str or exp_date_str == 'NEVER':
        return {'status': 'Permanent', 'expires_on': None, 'is_expired': False}
    try:
        exp_date = datetime.strptime(exp_date_str.strip(), '%Y-%m-%d')
        today = datetime.now()
        is_expired = exp_date < today
        if is_expired:
            return {'status': 'Expired', 'expires_on': exp_date_str, 'is_expired': True}
        return {'status': f'Expires on {exp_date_str}', 'expires_on': exp_date_str, 'is_expired': False}
    except (ValueError, TypeError, AttributeError):
        return {'status': 'Permanent', 'expires_on': None, 'is_expired': False}


def _exp_str_to_datetime(exp_str):
    """Convert legacy EXP string to datetime or None for DB."""
    if not exp_str or exp_str.strip().upper() == 'NEVER':
        return None
    try:
        return datetime.strptime(exp_str.strip(), '%Y-%m-%d')
    except (ValueError, TypeError, AttributeError):
        return None


def migrate_legacy_data():
    """Import data from data/Main/*.txt and yara.txt into SQLite. Run only when DB has no IOCs."""
    if db.session.query(IOC).limit(1).first() is not None:
        return
    print("[Migration] Empty DB detected. Importing legacy data from data/Main/...")
    # IOC types that have their own files (exclude YARA - handled separately)
    ioc_types = [k for k in IOC_FILES if k != 'YARA']
    for ioc_type in ioc_types:
        filename = IOC_FILES.get(ioc_type)
        if not filename:
            continue
        filepath = os.path.join(DATA_MAIN, filename)
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parsed = _parse_ioc_line_permissive(line)
                    if not parsed or not parsed.get('ioc'):
                        continue
                    value = (parsed.get('ioc') or '').strip()
                    if not value:
                        continue
                    analyst = (parsed.get('user') or '').strip().lower() or 'unknown'
                    ticket_id = (parsed.get('ref') or '').strip() or None
                    comment = (parsed.get('comment') or '').strip() or None
                    exp_str = parsed.get('expiration')
                    exp_dt = _exp_str_to_datetime(exp_str)
                    date_str = (parsed.get('date') or '').strip()
                    try:
                        created = datetime.fromisoformat(date_str.replace('Z', '+00:00')) if date_str else _utcnow()
                        if created.tzinfo:
                            created = created.replace(tzinfo=None)
                    except (ValueError, TypeError):
                        created = _utcnow()
                    try:
                        db.session.add(_create_ioc(
                            ioc_type, value, analyst, 'import',
                            ticket_id=ticket_id, comment=comment,
                            expiration_date=exp_dt, created_at=created,
                            user_id=1,
                        ))
                        _commit_with_retry()
                    except IntegrityError:
                        db.session.rollback()
                        continue
        except Exception as e:
            print(f"[Migration] Error reading {filename}: {e}")
            db.session.rollback()
            continue
    # Migrate yara.txt metadata into YaraRule
    if os.path.isfile(FILE_YARA):
        try:
            with open(FILE_YARA, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    parsed = _parse_ioc_line_permissive(line)
                    if not parsed or not parsed.get('ioc'):
                        continue
                    filename_yar = (parsed.get('ioc') or '').strip()
                    if not filename_yar.lower().endswith('.yar'):
                        continue
                    analyst = (parsed.get('user') or '').strip().lower() or 'upload'
                    ticket_id = (parsed.get('ref') or '').strip() or None
                    comment = (parsed.get('comment') or '').strip() or 'Uploaded YARA Rule'
                    date_str = (parsed.get('date') or '').strip()
                    try:
                        uploaded = datetime.fromisoformat(date_str.replace('Z', '+00:00')) if date_str else _utcnow()
                        if uploaded.tzinfo:
                            uploaded = uploaded.replace(tzinfo=None)
                    except (ValueError, TypeError):
                        uploaded = _utcnow()
                    try:
                        existing = YaraRule.query.filter_by(filename=filename_yar).first()
                        if not existing:
                            db.session.add(YaraRule(
                                filename=filename_yar,
                                analyst=analyst,
                                ticket_id=ticket_id,
                                comment=comment,
                                uploaded_at=uploaded
                            ))
                    except IntegrityError:
                        pass
            _commit_with_retry()
        except Exception as e:
            print(f"[Migration] Error reading yara.txt: {e}")
            db.session.rollback()
    print("[Migration] Legacy data import complete.")


def _tag_matches(tags_field, query_lower):
    """Return True if any tag in the tags JSON field contains query_lower."""
    if not tags_field:
        return False
    try:
        tags = json.loads(tags_field) if isinstance(tags_field, str) else tags_field
        return any(query_lower in (str(t).lower()) for t in (tags or []))
    except (TypeError, ValueError):
        return False


def _search_expiration_status_matches(row, query_lower):
    """Return True if the row's expiration status (Active/Expired/Permanent) matches query_lower."""
    exp_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
    status = check_expiration_status(exp_str)
    label = (status.get('status') or 'Active').lower()
    return query_lower in label or query_lower in exp_str.lower()


def _history_deleted_to_search_result(h):
    """Build a search-result dict from an IocHistory 'deleted' row (same shape as frontend expects)."""
    payload = {}
    if h.payload:
        try:
            payload = json.loads(h.payload)
        except (TypeError, ValueError):
            pass
    comment = (payload.get('comment') or '') if payload else ''
    expiration_str = (payload.get('expiration_date') or '')[:10] if payload.get('expiration_date') else 'NEVER'
    date_str = h.at.isoformat() if h.at else None
    return {
        'ioc': h.ioc_value,
        'value': h.ioc_value,
        'date': date_str,
        'user': h.username or '',
        'ref': '',
        'comment': comment,
        'expiration': expiration_str,
        'file_type': h.ioc_type,
        'line_number': None,
        'raw_line': f"{h.ioc_value} # Deleted at {date_str}",
        'expiration_status': 'Deleted',
        'expires_on': None,
        'is_expired': True,
        'status': 'Deleted',
        'campaign_name': None,
        'tags': [],
    }


def _deleted_history_matches(h, query_lower, filter_type):
    """Return True if this IocHistory deleted row matches the search query for the given filter."""
    payload = {}
    if h.payload:
        try:
            payload = json.loads(h.payload)
        except (TypeError, ValueError):
            pass
    comment = (payload.get('comment') or '').lower()
    value_lower = (h.ioc_value or '').lower()
    user_lower = (h.username or '').lower()
    date_str = (h.at.isoformat() if h.at else '').lower()
    if filter_type == 'all':
        return (
            query_lower in value_lower or
            query_lower in user_lower or
            query_lower in date_str or
            query_lower in comment or
            query_lower in (h.ioc_type or '').lower() or
            query_lower in 'deleted'
        )
    if filter_type == 'ioc_value':
        return query_lower in value_lower
    if filter_type == 'user':
        return query_lower in user_lower
    if filter_type == 'comment':
        return query_lower in comment
    if filter_type == 'date':
        return query_lower in date_str
    if filter_type == 'file_type':
        return query_lower in (h.ioc_type or '').lower() or query_lower == 'yara'
    if filter_type == 'expiration_status':
        return query_lower in 'deleted'
    if filter_type == 'ticket_id':
        ref = (payload.get('ticket_id') or '').lower()
        return query_lower in ref
    if filter_type == 'tag':
        tags = payload.get('tags') or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (TypeError, ValueError):
                tags = []
        return any(query_lower in (str(t).lower()) for t in tags)
    return False


def _ioc_row_to_search_result(row, ioc_type, query_lower, filter_type):
    """Build a search-result dict from an IOC row (same shape as frontend expects)."""
    expiration_str = row.expiration_date.strftime('%Y-%m-%d') if row.expiration_date else 'NEVER'
    exp_status = check_expiration_status(expiration_str)
    date_str = row.created_at.isoformat() if row.created_at else None
    campaign_name = None
    if row.campaign_id and row.campaign:
        campaign_name = row.campaign.name
    result = {
        'ioc': row.value,
        'date': date_str,
        'user': row.analyst or '',
        'ref': row.ticket_id or '',
        'comment': row.comment or '',
        'expiration': expiration_str,
        'file_type': ioc_type,
        'line_number': row.id,
        'raw_line': f"{row.value} # Date:{date_str} | User:{row.analyst} | Ref:{row.ticket_id or ''} | Comment:{row.comment or ''} | EXP:{expiration_str}",
        'expiration_status': exp_status['status'],
        'expires_on': exp_status['expires_on'],
        'is_expired': exp_status['is_expired'],
        'status': 'Expired' if exp_status['is_expired'] else 'Active',
        'campaign_name': campaign_name,
    }
    if getattr(row, 'tags', None):
        try:
            result['tags'] = json.loads(row.tags) if isinstance(row.tags, str) else (row.tags or [])
        except (TypeError, ValueError):
            result['tags'] = []
    else:
        result['tags'] = []
    if ioc_type == 'IP':
        result['country_code'] = get_country_code(row.value)
    return result


def _startup_diagnostic():
    """Log files in data/Main/ and their line counts for debugging stats issues."""
    target_dir = os.path.abspath(DATA_MAIN)
    if not os.path.isdir(target_dir):
        print(f"[DIAGNOSTIC] Directory does not exist: {target_dir}")
        return
    try:
        entries = sorted(os.listdir(target_dir))
        for name in entries:
            full_path = os.path.abspath(os.path.join(target_dir, name))
            if not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                    line_count = sum(1 for _ in f)
            except Exception as e:
                line_count = f"Error: {e}"
            print(f"[DIAGNOSTIC] File: {name} | Lines: {line_count} | Path: {full_path}")
    except Exception as e:
        print(f"[DIAGNOSTIC] Failed to list {target_dir}: {e}")


def _ensure_yara_campaign_id_column():
    """If yara_rules table exists without campaign_id, add it (migration safety)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(yara_rules)"))
        rows = result.fetchall()
        has_campaign_id = any((row[1] == 'campaign_id' for row in rows))
        if not has_campaign_id:
            db.session.execute(text(
                "ALTER TABLE yara_rules ADD COLUMN campaign_id INTEGER REFERENCES campaigns(id)"
            ))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] yara_rules campaign_id check/add: {e}")


def _ensure_yara_quality_points_column():
    """Add quality_points to yara_rules for Champs YARA scoring (10-50 per rule)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(yara_rules)"))
        rows = result.fetchall()
        has_qp = any((row[1] == 'quality_points' for row in rows))
        if not has_qp:
            db.session.execute(text("ALTER TABLE yara_rules ADD COLUMN quality_points INTEGER"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] yara_rules quality_points check/add: {e}")


def _ensure_yara_status_column():
    """Add status to yara_rules for approval workflow (pending | approved | rejected)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(yara_rules)"))
        rows = result.fetchall()
        has_status = any((row[1] == 'status' for row in rows))
        if not has_status:
            db.session.execute(text(
                "ALTER TABLE yara_rules ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT 'approved'"
            ))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] yara_rules status check/add: {e}")


def _ensure_ioc_submission_method_column():
    """Add submission_method to iocs if missing (single|csv|txt|paste|import)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(iocs)"))
        rows = result.fetchall()
        if not any(row[1] == 'submission_method' for row in rows):
            db.session.execute(text("ALTER TABLE iocs ADD COLUMN submission_method VARCHAR(16) DEFAULT 'single'"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] iocs submission_method check/add: {e}")


def _ensure_ioc_tags_column():
    """If iocs table exists without tags column, add it (migration safety)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(iocs)"))
        rows = result.fetchall()
        has_tags = any((row[1] == 'tags' for row in rows))
        if not has_tags:
            db.session.execute(text("ALTER TABLE iocs ADD COLUMN tags TEXT DEFAULT '[]'"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] iocs tags check/add: {e}")


def _ensure_ioc_rare_find_columns():
    """Add Rare Find columns to iocs if missing (country_code, tld, email_domain, rare_find_type)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(iocs)"))
        rows = result.fetchall()
        names = {row[1] for row in rows}
        if 'country_code' not in names:
            db.session.execute(text("ALTER TABLE iocs ADD COLUMN country_code VARCHAR(8)"))
            _commit_with_retry()
        if 'tld' not in names:
            db.session.execute(text("ALTER TABLE iocs ADD COLUMN tld VARCHAR(32)"))
            _commit_with_retry()
        if 'email_domain' not in names:
            db.session.execute(text("ALTER TABLE iocs ADD COLUMN email_domain VARCHAR(255)"))
            _commit_with_retry()
        if 'rare_find_type' not in names:
            db.session.execute(text("ALTER TABLE iocs ADD COLUMN rare_find_type VARCHAR(32)"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] iocs rare_find columns: {e}")


def _ensure_admin_user():
    """Create default admin user if no users exist (offline-friendly)."""
    if User.query.limit(1).first() is not None:
        return
    default_password = os.environ.get('ADMIN_DEFAULT_PASSWORD', 'admin')
    admin = User(
        username='admin',
        password_hash=hash_password(default_password),
        source='local',
        is_admin=True,
        is_active=True,
        must_change_password=True,
    )
    db.session.add(admin)
    _commit_with_retry()
    print("[Migration] Created default admin user (must_change_password=True).")
    profile = UserProfile(user_id=admin.id, display_name='Administrator')
    db.session.add(profile)
    _commit_with_retry()


def _ensure_system_settings_table():
    """Ensure system_settings table exists (Phase 2.5 config storage)."""
    try:
        db.create_all()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] system_settings: {e}")


def _ensure_user_last_login_column():
    """Add last_login_at to users if missing."""
    try:
        result = db.session.execute(text("PRAGMA table_info(users)"))
        rows = result.fetchall()
        has_col = any((row[1] == 'last_login_at' for row in rows))
        if not has_col:
            db.session.execute(text("ALTER TABLE users ADD COLUMN last_login_at DATETIME"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] users last_login_at: {e}")


def _ensure_user_must_change_password_column():
    """Add must_change_password to users if missing; set True for default admin."""
    try:
        result = db.session.execute(text("PRAGMA table_info(users)"))
        rows = result.fetchall()
        has_col = any((row[1] == 'must_change_password' for row in rows))
        if not has_col:
            db.session.execute(text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] users must_change_password: {e}")


def _ensure_ioc_user_id_column():
    """Add user_id to iocs if missing; assign existing IOCs to admin (id=1)."""
    try:
        result = db.session.execute(text("PRAGMA table_info(iocs)"))
        rows = result.fetchall()
        has_user_id = any((row[1] == 'user_id' for row in rows))
        if not has_user_id:
            db.session.execute(text("ALTER TABLE iocs ADD COLUMN user_id INTEGER REFERENCES users(id)"))
            _commit_with_retry()
        admin = db.session.get(User, 1)
        if admin:
            db.session.execute(text("UPDATE iocs SET user_id = 1 WHERE user_id IS NULL"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] iocs user_id check/add: {e}")


def _ensure_team_goal_type_column():
    """Add goal_type to team_goals if missing."""
    try:
        result = db.session.execute(text("PRAGMA table_info(team_goals)"))
        rows = result.fetchall()
        if not rows:
            return
        has_goal_type = any((row[1] == 'goal_type' for row in rows))
        if not has_goal_type:
            db.session.execute(text("ALTER TABLE team_goals ADD COLUMN goal_type VARCHAR(32) DEFAULT 'ioc_add' NOT NULL"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] team_goals goal_type: {e}")


def _ensure_team_goal_description_column():
    """Add description to team_goals if missing."""
    try:
        result = db.session.execute(text("PRAGMA table_info(team_goals)"))
        rows = result.fetchall()
        if not rows:
            return
        has_desc = any((row[1] == 'description' for row in rows))
        if not has_desc:
            db.session.execute(text("ALTER TABLE team_goals ADD COLUMN description TEXT"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] team_goals description: {e}")


def _ensure_campaign_dir_column():
    """Add dir (ltr/rtl) to campaigns if missing."""
    try:
        result = db.session.execute(text("PRAGMA table_info(campaigns)"))
        rows = result.fetchall()
        if not rows:
            return
        has_dir = any((row[1] == 'dir' for row in rows))
        if not has_dir:
            db.session.execute(text("ALTER TABLE campaigns ADD COLUMN dir VARCHAR(8) DEFAULT 'ltr'"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] campaigns dir: {e}")


def _ensure_campaign_created_by_column():
    """Add created_by (user_id) to campaigns if missing."""
    try:
        result = db.session.execute(text("PRAGMA table_info(campaigns)"))
        rows = result.fetchall()
        if not rows:
            return
        has_created_by = any((row[1] == 'created_by' for row in rows))
        if not has_created_by:
            db.session.execute(text("ALTER TABLE campaigns ADD COLUMN created_by INTEGER REFERENCES users(id)"))
            _commit_with_retry()
    except Exception as e:
        db.session.rollback()
        print(f"[Migration] campaigns created_by: {e}")


def _init_db():
    """Create tables and run legacy migration if DB is empty."""
    with app.app_context():
        db.create_all()
        _ensure_yara_campaign_id_column()
        _ensure_yara_quality_points_column()
        _ensure_yara_status_column()
        _ensure_ioc_tags_column()
        _ensure_ioc_submission_method_column()
        _ensure_ioc_rare_find_columns()
        _ensure_user_last_login_column()  # Must run before any User query (admin_user, etc.)
        _ensure_user_must_change_password_column()
        _ensure_admin_user()  # Must exist before user_id migration
        _ensure_ioc_user_id_column()
        _ensure_system_settings_table()
        _ensure_team_goal_type_column()
        _ensure_team_goal_description_column()
        _ensure_campaign_dir_column()
        _ensure_campaign_created_by_column()
        migrate_legacy_data()


# Ensure DB exists when app is loaded (e.g. under gunicorn); avoids service crash on first start
try:
    _init_db()
except Exception:
    pass


if __name__ == '__main__':
    _init_db()
    port = int(os.environ.get('FLASK_PORT', 5000))
    use_ssl = os.path.isfile(SSL_CERT_FILE) and os.path.isfile(SSL_KEY_FILE)
    if use_ssl:
        app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
                host='0.0.0.0',
                port=port,
                ssl_context=(SSL_CERT_FILE, SSL_KEY_FILE))
    else:
        app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
                host='0.0.0.0',
                port=port)
