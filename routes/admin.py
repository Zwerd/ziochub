"""
Admin routes: API (url_prefix='/api/admin') and HTML pages (url_prefix='/admin').
Uses lazy imports from app for shared helpers to avoid circular imports.
"""
import logging
import os

from flask import Blueprint, request, jsonify, url_for, redirect, render_template
from flask_login import current_user
from sqlalchemy.exc import IntegrityError

from sqlalchemy.exc import OperationalError

from extensions import db
from models import User, UserProfile, SystemSetting
from utils.auth import hash_password
from utils.decorators import admin_required, admin_required_page
from utils.allowlist import clear_allowlist_cache
from routes.auth import _save_avatar, AVATARS_DIR, ALLOWED_AVATAR_EXT


# --- Admin API blueprint ---
bp = Blueprint('admin_api', __name__, url_prefix='/api/admin')

# --- Admin HTML pages blueprint ---
pages_bp = Blueprint('admin_pages', __name__, url_prefix='/admin')

# Scoring methods for Champs (used by admin scoring page)
SCORING_METHODS = [
    {'id': '1', 'name': 'Weighted + Streak', 'description': 'IOC: 2 pts (3 if linked to campaign). YARA: 10-50 pts by rule quality. Expired deletion: 1 pt. Bonus: 10% for 3+ consecutive days of activity.'},
    {'id': '2', 'name': 'Flat', 'description': '1 point per IOC regardless of type or campaign. Fixed points per YARA rule. Simple total with no bonuses.'},
    {'id': '3', 'name': 'By Type', 'description': 'Different points per IOC type: e.g. IP=3, Domain=2, Hash=4, URL=2, Email=2. YARA in a fixed range. Reflects perceived value or difficulty of each type.'},
    {'id': '4', 'name': 'Campaign Focus', 'description': 'Little or no points for IOCs without a campaign. Full points only for campaign-linked IOCs and YARA. Encourages structured, campaign-driven work.'},
    {'id': '5', 'name': 'Time Decay', 'description': 'Recent activity counts full; older activity is discounted (e.g. last 7 days 100%, 8-30 days 50%, 31-90 days 25%). Emphasizes current contribution.'},
    {'id': '6', 'name': 'Quality', 'description': 'Base points plus bonus for comment, tags, campaign, ticket ID, and TTL. Rewards rich metadata and curation over bulk submission.'},
    {'id': '7', 'name': 'Goal-Based', 'description': 'Points (or contribution share) count mainly when contributing to an active team goal. Aligns scoring with current team targets.'},
    {'id': '8', 'name': 'Smart (Effort)', 'description': 'Rewards genuine effort over bulk ingestion. IOCs: single submit = 2 pts base, bulk (CSV/TXT/Paste) = 1 pt base. +1 for meaningful comment (unique per batch; duplicated comments ignored). +1 for campaign link. Range: 1-4 pts/IOC. YARA: 10 base pts on upload; full quality score (10-50) unlocks only after admin approval. Badges decay fast (1-7 days of inactivity).'},
]


def _from_app(*names):
    """Lazy import from app to avoid circular import."""
    import app as _app
    return tuple(getattr(_app, n) for n in names)


# --- Certificate ---

@bp.route('/certificate/status', methods=['GET'])
@admin_required
def certificate_status():
    """Return current certificate status (present, expiry)."""
    _certificate_status, = _from_app('_certificate_status')
    return jsonify({'success': True, 'certificate': _certificate_status()})


@bp.route('/certificate', methods=['POST'])
@admin_required
def certificate_save():
    """Save SSL certificate and private key (PEM)."""
    _api_error, _certificate_status, audit_log = _from_app('_api_error', '_certificate_status', 'audit_log')
    try:
        data = request.get_json() or {}
        cert_pem = (data.get('cert_pem') or '').strip()
        key_pem = (data.get('key_pem') or '').strip()
        ca_pem = (data.get('ca_pem') or '').strip()
        if not cert_pem or not key_pem:
            return jsonify({'success': False, 'message': 'Certificate and private key are required.'}), 400
        if '-----BEGIN' not in cert_pem or '-----END' not in cert_pem:
            return jsonify({'success': False, 'message': 'Invalid certificate PEM (expect -----BEGIN CERTIFICATE----- / -----END CERTIFICATE-----).'}), 400
        if '-----BEGIN' not in key_pem or '-----END' not in key_pem:
            return jsonify({'success': False, 'message': 'Invalid private key PEM (expect -----BEGIN ... PRIVATE KEY----- / -----END ... PRIVATE KEY-----).'}), 400
        SSL_DIR, SSL_CERT_FILE, SSL_KEY_FILE, SSL_CA_FILE = _from_app('SSL_DIR', 'SSL_CERT_FILE', 'SSL_KEY_FILE', 'SSL_CA_FILE')
        os.makedirs(SSL_DIR, exist_ok=True)
        with open(SSL_CERT_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(cert_pem)
        with open(SSL_KEY_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(key_pem)
        try:
            os.chmod(SSL_KEY_FILE, 0o600)
        except OSError:
            pass
        if ca_pem and ('-----BEGIN' in ca_pem and '-----END' in ca_pem):
            with open(SSL_CA_FILE, 'w', encoding='utf-8', newline='\n') as f:
                f.write(ca_pem)
        elif os.path.isfile(SSL_CA_FILE):
            try:
                os.remove(SSL_CA_FILE)
            except OSError:
                pass
        audit_log('admin_certificate_save', f'by={current_user.username}')
        return jsonify({
            'success': True,
            'message': 'Certificate saved. Restart the application (or reverse proxy) with HTTPS to use it.',
            'certificate': _certificate_status()
        })
    except Exception as e:
        logging.exception('api_admin_certificate_save failed')
        return _api_error(str(e), 500)


# --- Scoring method ---

@bp.route('/scoring-method', methods=['GET'])
@admin_required
def get_scoring_method():
    """Get current Champs scoring method (1-8)."""
    _api_ok, _get_setting = _from_app('_api_ok', '_get_setting')
    method = _get_setting('champs_scoring_method', '1')
    return _api_ok(data={'method': method})


@bp.route('/scoring-method', methods=['POST'])
@admin_required
def save_scoring_method():
    """Save Champs scoring method (1-8)."""
    _api_ok, _api_error, _set_setting, audit_log = _from_app('_api_ok', '_api_error', '_set_setting', 'audit_log')
    try:
        data = request.get_json() or {}
        method = str(data.get('method', '1')).strip()
        if method not in ('1', '2', '3', '4', '5', '6', '7', '8'):
            return jsonify({'success': False, 'message': 'Invalid method. Use 1-8.'}), 400
        _set_setting('champs_scoring_method', method)
        audit_log('admin_scoring_method_update', f'method={method} by={current_user.username}')
        return _api_ok(message='Scoring method saved.')
    except Exception as e:
        logging.exception('api_admin_save_scoring_method failed')
        return _api_error(str(e), 500)


# --- Settings ---

_SETTINGS_DEFAULTS = {
    'auth_mode': 'local_only',
    'ldap_enabled': 'false',
    'ldap_url': '',
    'ldap_base_dn': '',
    'ldap_bind_dn': '',
    'ldap_bind_password': '',
    'ldap_user_filter': '(sAMAccountName=%(user)s)',
    'misp_enabled': 'false',
    'misp_url': '',
    'misp_api_key': '',
    'misp_verify_ssl': 'false',
    'misp_last_days': '30',
    'misp_filter_tags': '',
    'misp_filter_types': '',
    'misp_published_only': 'true',
    'misp_default_ttl': 'permanent',
    'misp_sync_user': 'misp_sync',
    'misp_pull_interval': '60',
    'misp_last_sync': '',
    'misp_last_sync_result': '',
    'misp_exclude_from_champs': 'true',
    'syslog_udp_enabled': 'false',
    'syslog_udp_host': '',
    'syslog_udp_port': '514',
}


@bp.route('/settings', methods=['GET'])
@admin_required
def get_settings():
    """Get all system settings (JSON API)."""
    _api_ok, _ensure_system_settings_table = _from_app('_api_ok', '_ensure_system_settings_table')
    settings = dict(_SETTINGS_DEFAULTS)
    try:
        rows = SystemSetting.query.all()
        for r in rows:
            settings[r.key] = (r.value or '') if r.value is not None else ''
    except OperationalError:
        try:
            _ensure_system_settings_table()
            rows = SystemSetting.query.all()
            for r in rows:
                settings[r.key] = (r.value or '') if r.value is not None else ''
        except Exception:
            pass
    for k, v in _SETTINGS_DEFAULTS.items():
        if k not in settings:
            settings[k] = v
    return _api_ok(data={'settings': settings})


# MISP keys (fallback when misp_settings module is missing, e.g. old install)
_MISP_SAVE_KEYS_FALLBACK = (
    'misp_enabled', 'misp_url', 'misp_api_key', 'misp_verify_ssl', 'misp_last_days',
    'misp_filter_tags', 'misp_filter_types', 'misp_published_only', 'misp_default_ttl',
    'misp_sync_user', 'misp_pull_interval', 'misp_exclude_from_champs',
)
_MISP_SYNC_KEYS_FALLBACK = (
    'misp_url', 'misp_api_key', 'misp_verify_ssl', 'misp_last_days',
    'misp_filter_tags', 'misp_filter_types', 'misp_published_only', 'misp_default_ttl', 'misp_sync_user',
)


@bp.route('/settings', methods=['POST'])
@admin_required
def save_settings():
    """Save system settings (JSON API)."""
    _api_ok, _api_error, _set_setting, _get_setting, audit_log = _from_app('_api_ok', '_api_error', '_set_setting', '_get_setting', 'audit_log')
    try:
        data = request.get_json() or {}
        try:
            from misp_settings import MISP_SAVE_KEYS
            misp_keys = MISP_SAVE_KEYS
        except ImportError:
            misp_keys = _MISP_SAVE_KEYS_FALLBACK
        syslog_keys = ('syslog_udp_enabled', 'syslog_udp_host', 'syslog_udp_port')
        ldap_keys = ('auth_mode', 'ldap_enabled', 'ldap_url', 'ldap_base_dn', 'ldap_bind_dn', 'ldap_bind_password', 'ldap_user_filter')
        sections = []
        for key in ldap_keys + misp_keys + syslog_keys:
            if key in data:
                _set_setting(key, str(data[key]).strip())
                if key in ldap_keys and 'LDAP' not in sections:
                    sections.append('LDAP')
                elif key in misp_keys and 'MISP' not in sections:
                    sections.append('MISP')
                elif key in syslog_keys and 'Syslog' not in sections:
                    sections.append('Syslog')
        try:
            from utils.cef_logger import refresh_cef_udp_target
            udp_enabled = _get_setting('syslog_udp_enabled', 'false').lower() == 'true'
            udp_host = _get_setting('syslog_udp_host', '').strip() if udp_enabled else ''
            udp_port = int(_get_setting('syslog_udp_port', '514') or '514')
            refresh_cef_udp_target(udp_host, udp_port)
        except Exception:
            pass
        detail = ','.join(sections) if sections else 'settings'
        audit_log('admin_settings_update', f'{detail} by={current_user.username}')
        return _api_ok(message='Settings saved')
    except Exception as e:
        logging.exception('api_admin_save_settings failed')
        return _api_error(str(e), 500)


@bp.route('/ldap/test', methods=['POST'])
@admin_required
def ldap_test():
    """Run LDAP connection test step-by-step; return list of steps for Admin UI."""
    _api_ok, _api_error = _from_app('_api_ok', '_api_error')
    try:
        from utils.ldap_auth import test_ldap_connection_steps
        data = request.get_json() or {}
        ldap_url = (data.get('ldap_url') or '').strip()
        base_dn = (data.get('ldap_base_dn') or '').strip()
        bind_dn = (data.get('ldap_bind_dn') or '').strip()
        bind_password = data.get('ldap_bind_password') or ''
        steps = test_ldap_connection_steps(ldap_url, base_dn, bind_dn, bind_password)
        success = all(s.get('status') == 'ok' for s in steps)
        return _api_ok(data={'success': success, 'steps': steps})
    except Exception as e:
        logging.exception('admin ldap_test failed')
        return _api_error(str(e), 500)


@bp.route('/logs/tail')
@admin_required
def logs_tail():
    """Return last N lines of CEF audit log (default 50)."""
    _api_ok, _api_error, get_audit_log_path = _from_app('_api_ok', '_api_error', 'get_audit_log_path')
    try:
        lines = min(int(request.args.get('lines', 50)), 500)
        log_path = get_audit_log_path()
        if not os.path.isfile(log_path):
            return _api_ok(data={'lines': [], 'path': log_path, 'message': 'Log file not found or empty.'})
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            all_lines = f.readlines()
        last = all_lines[-lines:] if len(all_lines) >= lines else all_lines
        return _api_ok(data={'lines': [ln.rstrip('\n\r') for ln in last], 'path': log_path})
    except Exception as e:
        logging.exception('admin logs_tail failed')
        return _api_error(str(e), 500)


# --- Users ---

def _avatar_url(profile):
    """Return avatar URL or None (used in list)."""
    if profile and profile.avatar_path:
        return url_for('static', filename=profile.avatar_path)
    return None


@bp.route('/users', methods=['GET'])
@admin_required
def list_users():
    """List all users (username, source, is_admin, last login, avatar_url)."""
    _api_ok = _from_app('_api_ok')[0]
    users = User.query.order_by(User.username).all()
    result = []
    for u in users:
        profile = UserProfile.query.filter_by(user_id=u.id).first()
        result.append({
            'id': u.id,
            'username': u.username,
            'source': u.source,
            'is_admin': u.is_admin,
            'is_active': u.is_active,
            'must_change_password': getattr(u, 'must_change_password', False),
            'display_name': (profile and profile.display_name) or u.username,
            'avatar_url': _avatar_url(profile),
            'last_login_at': u.last_login_at.isoformat() if u.last_login_at else None,
            'created_at': u.created_at.isoformat() if u.created_at else None,
        })
    return _api_ok(data={'users': result})


@bp.route('/users', methods=['POST'])
@admin_required
def create_user():
    """Create a local user (admin only)."""
    _api_ok, _api_error, _commit_with_retry, audit_log = _from_app('_api_ok', '_api_error', '_commit_with_retry', 'audit_log')
    try:
        data = request.get_json() or {}
        username = (data.get('username') or '').strip().lower()
        password = data.get('password') or ''
        display_name = (data.get('display_name') or '').strip() or username
        is_admin = bool(data.get('is_admin', False))
        if not username:
            return jsonify({'success': False, 'message': 'Username is required'}), 400
        if len(username) < 2:
            return jsonify({'success': False, 'message': 'Username must be at least 2 characters'}), 400
        if not password or len(password) < 4:
            return jsonify({'success': False, 'message': 'Password must be at least 4 characters'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 409
        must_change = bool(data.get('must_change_password', False))
        user = User(
            username=username,
            password_hash=hash_password(password),
            source='local',
            is_admin=is_admin,
            is_active=True,
            must_change_password=must_change,
        )
        db.session.add(user)
        _commit_with_retry()
        profile = UserProfile(user_id=user.id, display_name=display_name)
        db.session.add(profile)
        _commit_with_retry()
        audit_log('admin_user_create', f'username={username} by={current_user.username}')
        return _api_ok(message=f'User {username} created', data={'id': user.id})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Username already exists'}), 409
    except Exception as e:
        logging.exception('api_admin_create_user failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    """Update a user (admin only). Local: full edit. LDAP: is_admin and display_name only."""
    _api_error, _commit_with_retry, audit_log = _from_app('_api_error', '_commit_with_retry', 'audit_log')
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        if user.source == 'system':
            return jsonify({'success': False, 'message': 'System users (e.g. MISP sync) cannot be edited'}), 400
        data = request.get_json() or {}
        is_ldap = user.source == 'ldap'

        if 'display_name' in data:
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            display_name = (data.get('display_name') or '').strip()
            if profile:
                profile.display_name = display_name or user.username
            else:
                db.session.add(UserProfile(user_id=user.id, display_name=display_name or user.username))
        if 'is_admin' in data:
            user.is_admin = bool(data['is_admin'])

        if not is_ldap:
            if 'password' in data and data['password']:
                pwd = str(data['password'])
                if len(pwd) < 4:
                    return jsonify({'success': False, 'message': 'Password must be at least 4 characters'}), 400
                user.password_hash = hash_password(pwd)
            if 'must_change_password' in data:
                user.must_change_password = bool(data['must_change_password'])

        _commit_with_retry()
        audit_log('admin_user_update', f'user_id={user_id} by={current_user.username}')
        return jsonify({'success': True, 'message': f'User {user.username} updated'})
    except Exception as e:
        logging.exception('api_admin_update_user failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>/avatar', methods=['POST'])
@admin_required
def user_avatar_upload(user_id):
    """Upload profile picture for a user (admin only)."""
    _api_ok, _api_error, _commit_with_retry, audit_log = _from_app(
        '_api_ok', '_api_error', '_commit_with_retry', 'audit_log'
    )
    try:
        user = db.session.get(User, user_id)
        if not user:
            return _api_error('User not found', 404)
        if 'file' not in request.files and 'avatar' not in request.files:
            return _api_error('No file provided', 400)
        file = request.files.get('file') or request.files.get('avatar')
        rel_path, err = _save_avatar(file, user_id, ALLOWED_AVATAR_EXT, AVATARS_DIR)
        if err:
            return _api_error(err, 400)
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if not profile:
            profile = UserProfile(user_id=user_id, display_name=user.username)
            db.session.add(profile)
        profile.avatar_path = rel_path
        _commit_with_retry()
        audit_log('admin_avatar_upload', f'user_id={user_id} username={user.username} by={current_user.username}')
        return _api_ok(data={'avatar_url': url_for('static', filename=rel_path)}, message='Profile picture updated')
    except Exception as e:
        logging.exception('api_admin_user_avatar_upload failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>/avatar', methods=['DELETE'])
@admin_required
def user_avatar_delete(user_id):
    """Remove profile picture of a user (admin only)."""
    _api_ok, _api_error, _commit_with_retry, audit_log = _from_app('_api_ok', '_api_error', '_commit_with_retry', 'audit_log')
    try:
        user = db.session.get(User, user_id)
        if not user:
            return _api_error('User not found', 404)
        profile = UserProfile.query.filter_by(user_id=user_id).first()
        if not profile or not profile.avatar_path:
            return _api_ok(data={'avatar_url': None}, message='No avatar to remove')
        old_path = profile.avatar_path
        profile.avatar_path = None
        _commit_with_retry()
        if old_path and old_path.startswith('avatars/'):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filepath = os.path.join(base_dir, 'static', old_path)
            if os.path.isfile(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass
        audit_log('admin_avatar_delete', f'user_id={user_id} username={user.username} by={current_user.username}')
        return _api_ok(data={'avatar_url': None}, message='Profile picture removed')
    except Exception as e:
        logging.exception('admin user_avatar_delete failed')
        return _api_error(str(e), 500)


@bp.route('/users/<int:user_id>/toggle-active', methods=['POST'])
@admin_required
def toggle_user_active(user_id):
    """Activate or deactivate a user (admin only)."""
    _api_error, _commit_with_retry, audit_log = _from_app('_api_error', '_commit_with_retry', 'audit_log')
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'You cannot deactivate yourself'}), 400
        user.is_active = not user.is_active
        _commit_with_retry()
        status = 'activated' if user.is_active else 'deactivated'
        audit_log('admin_user_toggle', f'user_id={user_id} status={status} by={current_user.username}')
        return jsonify({'success': True, 'message': f'User {user.username} {status}', 'is_active': user.is_active})
    except Exception as e:
        logging.exception('api_admin_toggle_user_active failed')
        return _api_error(str(e), 500)


# --- Allowlist management (admin only) ---

@bp.route('/allowlist', methods=['GET'])
@admin_required
def allowlist_get():
    """Return raw allowlist file content."""
    _api_ok, _api_error = _from_app('_api_ok', '_api_error')
    ALLOWLIST_FILE, = _from_app('ALLOWLIST_FILE')
    try:
        raw = ''
        try:
            with open(ALLOWLIST_FILE, 'r', encoding='utf-8', errors='replace') as f:
                raw = f.read()
        except OSError:
            raw = ''
        return _api_ok(data={'raw': raw})
    except Exception as e:
        logging.exception('admin allowlist_get failed')
        return _api_error(str(e), 500)


@bp.route('/allowlist', methods=['POST'])
@admin_required
def allowlist_save():
    """Replace allowlist file content with provided raw text."""
    _api_ok, _api_error, audit_log = _from_app('_api_ok', '_api_error', 'audit_log')
    ALLOWLIST_FILE, = _from_app('ALLOWLIST_FILE')
    try:
        data = request.get_json() or {}
        raw = data.get('raw')
        if raw is None:
            return _api_error('raw is required', 400)
        if not isinstance(raw, str):
            return _api_error('raw must be a string', 400)
        if len(raw) > 500_000:
            return _api_error('Allowlist too large (max 500KB)', 400)
        # Normalize line endings; keep comments as-is
        raw_norm = raw.replace('\r\n', '\n').replace('\r', '\n')
        os.makedirs(os.path.dirname(ALLOWLIST_FILE), exist_ok=True)
        with open(ALLOWLIST_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(raw_norm.strip() + '\n' if raw_norm.strip() else '')
        clear_allowlist_cache(ALLOWLIST_FILE)
        audit_log('admin_allowlist_save', f'by={current_user.username}')
        return _api_ok(message='Allowlist saved')
    except Exception as e:
        logging.exception('admin allowlist_save failed')
        return _api_error(str(e), 500)


@bp.route('/allowlist/reload', methods=['POST'])
@admin_required
def allowlist_reload():
    """Clear allowlist cache so next check reloads from disk."""
    _api_ok, _api_error, audit_log = _from_app('_api_ok', '_api_error', 'audit_log')
    ALLOWLIST_FILE, = _from_app('ALLOWLIST_FILE')
    try:
        clear_allowlist_cache(ALLOWLIST_FILE)
        audit_log('admin_allowlist_reload', f'by={current_user.username}')
        return _api_ok(message='Allowlist reloaded')
    except Exception as e:
        logging.exception('admin allowlist_reload failed')
        return _api_error(str(e), 500)


# --- MISP Integration ---

@bp.route('/misp/test', methods=['POST'])
@admin_required
def misp_test():
    """Test MISP connectivity step-by-step; return steps for Admin UI live log."""
    _api_ok, _api_error, _get_setting = _from_app('_api_ok', '_api_error', '_get_setting')
    try:
        data = request.get_json() or {}
        url = (data.get('misp_url') or _get_setting('misp_url', '')).strip()
        api_key = (data.get('misp_api_key') or _get_setting('misp_api_key', '')).strip()
        verify_ssl = (data.get('misp_verify_ssl') or _get_setting('misp_verify_ssl', 'false')).lower() == 'true'

        from utils.misp_sync import test_connection_steps
        steps = test_connection_steps(url, api_key, verify_ssl)
        success = all(s.get('status') == 'ok' for s in steps)
        return _api_ok(data={'success': success, 'steps': steps})
    except Exception as e:
        logging.exception('admin misp_test failed')
        return _api_error(str(e), 500)


@bp.route('/misp/sync', methods=['POST'])
@admin_required
def misp_sync_now():
    """Run MISP sync manually (admin only)."""
    _api_ok, _api_error, _get_setting, _set_setting, audit_log = _from_app(
        '_api_ok', '_api_error', '_get_setting', '_set_setting', 'audit_log'
    )
    try:
        try:
            from misp_settings import MISP_SYNC_KEYS
            sync_keys = MISP_SYNC_KEYS
        except ImportError:
            sync_keys = _MISP_SYNC_KEYS_FALLBACK
        settings = {key: _get_setting(key, '') for key in sync_keys}

        from utils.misp_sync import run_sync
        log_lines = []
        result = run_sync(settings, log_lines=log_lines)

        import json
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        _set_setting('misp_last_sync', now_str)
        _set_setting('misp_last_sync_result', json.dumps(result)[:1000])

        audit_log('misp_sync', f"manual by={current_user.username} added={result.get('added', 0)} skipped={result.get('skipped', 0)}")

        if result.get('success'):
            inv = result.get('invalid', 0)
            inv_msg = f", {inv} invalid" if inv else ''
            return _api_ok(
                message=f"Sync complete: {result.get('added', 0)} added, {result.get('skipped', 0)} duplicates skipped{inv_msg}",
                data={**result, 'steps': log_lines}
            )
        return jsonify({'success': False, 'message': result.get('error', 'Sync failed'), 'data': {**result, 'steps': log_lines}}), 400
    except Exception as e:
        logging.exception('admin misp_sync_now failed')
        return _api_error(str(e), 500)


# --- Admin HTML pages ---

@pages_bp.route('/')
@admin_required_page
def admin_index():
    """Admin dashboard - redirect to users list."""
    return redirect(url_for('admin_pages.admin_users'))


def _misp_settings_fallback(get_setting_fn):
    """Fallback MISP settings when misp_settings module is missing (e.g. old install)."""
    defaults = {
        'misp_enabled': 'false', 'misp_url': '', 'misp_api_key': '', 'misp_verify_ssl': 'false',
        'misp_last_days': '30', 'misp_filter_tags': '', 'misp_filter_types': '',
        'misp_published_only': 'true', 'misp_default_ttl': 'permanent', 'misp_sync_user': 'misp_sync',
        'misp_pull_interval': '60', 'misp_exclude_from_champs': 'true',
        'misp_last_sync': '', 'misp_last_sync_result': '',
    }
    return {k: str((get_setting_fn(k, v) if callable(get_setting_fn) else get_setting_fn.get(k, v)) or v).strip() or v for k, v in defaults.items()}


@pages_bp.route('/settings')
@admin_required_page
def admin_settings():
    """Admin settings page - configurable system settings (auth, LDAP, MISP)."""
    try:
        _get_setting, = _from_app('_get_setting')
        try:
            from misp_settings import get_settings_for_form
            misp_settings_dict = get_settings_for_form(_get_setting)
        except ImportError:
            misp_settings_dict = _misp_settings_fallback(_get_setting)
        settings = {
            'auth_mode': _get_setting('auth_mode', 'local_only'),
            'ldap_enabled': _get_setting('ldap_enabled', 'false'),
            'ldap_url': _get_setting('ldap_url', ''),
            'ldap_base_dn': _get_setting('ldap_base_dn', ''),
            'ldap_bind_dn': _get_setting('ldap_bind_dn', ''),
            'ldap_bind_password': _get_setting('ldap_bind_password', ''),
            'ldap_user_filter': _get_setting('ldap_user_filter', '(sAMAccountName=%(user)s)'),
            **misp_settings_dict,
            'syslog_udp_enabled': _get_setting('syslog_udp_enabled', 'false'),
            'syslog_udp_host': _get_setting('syslog_udp_host', ''),
            'syslog_udp_port': _get_setting('syslog_udp_port', '514'),
        }
        return render_template('admin/settings.html', settings=settings)
    except Exception:
        logging.exception('admin_settings page failed')
        from flask import abort
        abort(500)


@pages_bp.route('/allowlist')
@admin_required_page
def admin_allowlist():
    """Admin allowlist management page (known-good / critical assets)."""
    return render_template('admin/allowlist.html')


@pages_bp.route('/users')
@admin_required_page
def admin_users():
    """Admin users list page."""
    return render_template('admin/users.html')


@pages_bp.route('/scoring')
@admin_required_page
def admin_scoring():
    """Admin scoring method selection page (Champs)."""
    _get_setting, = _from_app('_get_setting')
    current = _get_setting('champs_scoring_method', '1')
    return render_template('admin/scoring.html', scoring_methods=SCORING_METHODS, current=current)


@pages_bp.route('/certificate')
@admin_required_page
def admin_certificate():
    """Admin SSL/TLS certificate settings - upload cert signed by local CA for HTTPS (prevent MITM)."""
    _certificate_status, = _from_app('_certificate_status')
    status = _certificate_status()
    return render_template('admin/certificate.html', cert_status=status)


@pages_bp.route('/logs')
@admin_required_page
def admin_logs():
    """Admin audit log viewer (CEF log, last 50 lines)."""
    return render_template('admin/logs.html')
