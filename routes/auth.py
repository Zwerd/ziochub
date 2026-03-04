"""Auth routes blueprint: login, logout, change-password, profile, LDAP health, users list."""
import logging
import os

from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from flask_login import login_user, logout_user, current_user

from extensions import db
from models import User, UserProfile, UserSession, _utcnow
from utils.auth import hash_password, verify_password
from utils.decorators import login_required
from utils.ldap_auth import try_ldap_bind, try_ldap_mock_dev, check_ldap_reachable, is_dev_mode

try:
    import config as _config
except ImportError:
    _config = None

bp = Blueprint('auth', __name__)

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _from_app(*names):
    """Lazy import from app to avoid circular import."""
    import app as _app
    return tuple(getattr(_app, n) for n in names)


# --- Constants ---
AVATARS_DIR = os.path.join(_project_root, 'static', 'avatars')
os.makedirs(AVATARS_DIR, exist_ok=True)
ALLOWED_AVATAR_EXT = frozenset({'jpg', 'jpeg', 'png', 'gif', 'webp'})


# --- Helpers ---

def _save_avatar(file, user_id: int, allowed_ext, base_path: str):
    """Save avatar file to base_path; validate extension. Returns (rel_path, None) or (None, error_message)."""
    if not file or (getattr(file, 'filename', None) or '').strip() == '':
        return None, 'No file selected'
    ext = (file.filename.rsplit('.', 1)[-1] or '').lower()
    if ext not in allowed_ext:
        return None, 'Allowed: jpg, png, gif, webp'
    safe_ext = 'jpg' if ext in ('jpg', 'jpeg') else ext
    filename = f"{user_id}.{safe_ext}"
    filepath = os.path.join(base_path, filename)
    file.save(filepath)
    rel_path = f"avatars/{filename}"
    return rel_path, None


def _login_required_page(f):
    """Require login for HTML; redirect to login if not authenticated."""
    from functools import wraps
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return wrapped


def _avatar_url(profile):
    """Return avatar URL or None for default placeholder. Phase 4."""
    if profile and profile.avatar_path:
        return url_for('static', filename=profile.avatar_path)
    return None


# --- Routes ---

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page. POST: authenticate (LDAP or local) and redirect to index."""
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        return render_template('login.html', dev_mode=is_dev_mode())
    username = (request.form.get('username') or '').strip().lower()
    password = request.form.get('password') or ''
    if not username or not password:
        return render_template('login.html', error='Username and password are required'), 400

    _get_setting, _commit_with_retry, audit_log = _from_app('_get_setting', '_commit_with_retry', 'audit_log')

    auth_mode = (_config and getattr(_config, 'AUTH_MODE', None)) or _get_setting('auth_mode', 'local_only') or 'local_only'
    ldap_enabled = _get_setting('ldap_enabled', 'false').lower() == 'true'
    user = None

    # Phase 6.2: Dev mode - devuser/dev auto-login as admin
    if is_dev_mode() and username == 'devuser' and password in ('dev', 'devuser'):
        admin_user = User.query.filter_by(is_admin=True, is_active=True).first()
        if admin_user:
            user = admin_user
            logging.info('Dev mode: auto-login as %s', admin_user.username)

    # Phase 3: Try LDAP first if enabled and auth_mode allows LDAP
    if ldap_enabled and auth_mode in ('ldap', 'ldap_with_local_fallback'):
        ldap_url = _get_setting('ldap_url', '').strip()
        ldap_base_dn = _get_setting('ldap_base_dn', '').strip()
        ldap_bind_dn = _get_setting('ldap_bind_dn', '').strip()
        ldap_bind_password = _get_setting('ldap_bind_password', '').strip()
        ldap_user_filter = _get_setting('ldap_user_filter', '(sAMAccountName=%(user)s)').strip()

        ldap_ok = False
        display_name = None
        if ldap_url and ldap_base_dn:
            ldap_ok, display_name = try_ldap_bind(
                ldap_url, ldap_base_dn, ldap_bind_dn, ldap_bind_password,
                ldap_user_filter, username, password,
            )
        if not ldap_ok:
            ldap_ok, display_name = try_ldap_mock_dev(username, password)
        if not ldap_ok and ldap_url and ldap_base_dn:
            logging.warning('Phase 6.3: LDAP unreachable for %s; falling back to local if auth_mode allows', username)
        if ldap_ok:
            user = User.query.filter_by(username=username).first()
            if user:
                user.source = 'ldap'
                user.password_hash = None
                user.is_active = True
            else:
                user = User(
                    username=username,
                    password_hash=None,
                    source='ldap',
                    is_admin=False,
                    is_active=True,
                )
                db.session.add(user)
                _commit_with_retry()
            profile = UserProfile.query.filter_by(user_id=user.id).first()
            if profile:
                profile.display_name = display_name or username
            else:
                db.session.add(UserProfile(user_id=user.id, display_name=display_name or username))
            _commit_with_retry()

    # Fallback to local auth
    if user is None and auth_mode in ('local_only', 'ldap_with_local_fallback'):
        local_user = User.query.filter_by(username=username, source='local', is_active=True).first()
        if local_user and verify_password(local_user.password_hash, password):
            user = local_user
        elif ldap_enabled and auth_mode == 'ldap_with_local_fallback':
            logging.warning('LDAP auth failed for %s, falling back to local', username)
        else:
            pass

    if user is None:
        return render_template('login.html', error='Invalid username or password'), 401

    login_user(user)
    user.last_login_at = _utcnow()
    usession = UserSession(user_id=user.id, ip_address=request.remote_addr)
    db.session.add(usession)
    _commit_with_retry()
    audit_log('login', f'user={username} source={user.source}')
    if user.must_change_password:
        return redirect(url_for('auth.change_password'))
    next_url = request.args.get('next') or url_for('index')
    return redirect(next_url)


@bp.route('/logout')
def logout():
    """Logout and redirect to index. Phase 5.2: update logout_at on user_sessions."""
    if current_user.is_authenticated:
        _commit_with_retry, audit_log = _from_app('_commit_with_retry', 'audit_log')
        open_session = UserSession.query.filter_by(
            user_id=current_user.id, logout_at=None
        ).order_by(UserSession.login_at.desc()).first()
        if open_session:
            open_session.logout_at = _utcnow()
            _commit_with_retry()
        audit_log('logout', f'user={current_user.username}')
        logout_user()
    return redirect(url_for('index'))


# --- Forced Password Change (first-login) ---

@bp.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Force password change page. Shown when must_change_password is True."""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    if not current_user.must_change_password:
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('change_password.html')

    old_password = request.form.get('old_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not old_password or not new_password or not confirm_password:
        return render_template('change_password.html', error='All fields are required')

    if not verify_password(current_user.password_hash, old_password):
        return render_template('change_password.html', error='Current password is incorrect')

    if new_password != confirm_password:
        return render_template('change_password.html', error='New passwords do not match')

    if len(new_password) < 8:
        return render_template('change_password.html', error='New password must be at least 8 characters')

    if old_password == new_password:
        return render_template('change_password.html', error='New password must be different from the current one')

    _commit_with_retry, audit_log = _from_app('_commit_with_retry', 'audit_log')
    current_user.password_hash = hash_password(new_password)
    current_user.must_change_password = False
    _commit_with_retry()
    audit_log('password_change', f'user={current_user.username} forced=true')
    return redirect(url_for('index'))


# --- Profile (Phase 4) ---

@bp.route('/profile')
@_login_required_page
def profile_page():
    """Profile edit page. Phase 4.1"""
    profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', profile=profile, user=current_user)


@bp.route('/api/profile', methods=['GET'])
@login_required
def api_profile_get():
    """Get current user profile. Phase 4.1"""
    profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    return jsonify({
        'success': True,
        'username': current_user.username,
        'source': current_user.source or 'local',
        'display_name': (profile and profile.display_name) or current_user.username,
        'role_description': (profile and profile.role_description) or '',
        'avatar_url': _avatar_url(profile),
    })


@bp.route('/api/profile', methods=['PUT'])
@login_required
def api_profile_update():
    """Update display_name, role_description. Phase 4.1"""
    _api_error, _commit_with_retry, audit_log = _from_app('_api_error', '_commit_with_retry', 'audit_log')
    try:
        data = request.get_json() or {}
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        if not profile:
            profile = UserProfile(user_id=current_user.id)
            db.session.add(profile)
        if 'display_name' in data:
            profile.display_name = (str(data['display_name']).strip() or current_user.username)[:255]
        if 'role_description' in data:
            profile.role_description = (str(data['role_description']).strip() or None)
        _commit_with_retry()
        audit_log('profile_update', f'user={current_user.username}')
        return jsonify({
            'success': True,
            'message': 'Profile updated',
            'display_name': profile.display_name,
            'avatar_url': _avatar_url(profile),
        })
    except Exception as e:
        logging.exception('api_profile_update failed')
        return _api_error(str(e), 500)


@bp.route('/api/profile/avatar', methods=['POST'])
@login_required
def api_profile_avatar_upload():
    """Upload avatar. Saves to static/avatars/{user_id}.{ext}. Phase 4.2"""
    _api_error, _api_ok, _commit_with_retry, audit_log = _from_app(
        '_api_error', '_api_ok', '_commit_with_retry', 'audit_log')
    try:
        if 'file' not in request.files and 'avatar' not in request.files:
            return _api_error('No file provided', 400)
        file = request.files.get('file') or request.files.get('avatar')
        rel_path, err = _save_avatar(file, current_user.id, ALLOWED_AVATAR_EXT, AVATARS_DIR)
        if err:
            return _api_error(err, 400)
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        if not profile:
            profile = UserProfile(user_id=current_user.id)
            db.session.add(profile)
        profile.avatar_path = rel_path
        _commit_with_retry()
        audit_log('avatar_upload', f'user={current_user.username}')
        return _api_ok(data={'avatar_url': url_for('static', filename=rel_path)}, message='Avatar uploaded')
    except Exception as e:
        logging.exception('api_profile_avatar_upload failed')
        return _api_error(str(e), 500)


@bp.route('/api/profile/avatar', methods=['DELETE'])
@login_required
def api_profile_avatar_delete():
    """Remove profile picture. Clears avatar_path and deletes file from disk if present."""
    _api_error, _api_ok, _commit_with_retry, audit_log = _from_app(
        '_api_error', '_api_ok', '_commit_with_retry', 'audit_log')
    try:
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        if not profile or not profile.avatar_path:
            return _api_ok(data={'avatar_url': None}, message='No avatar to remove')
        old_path = profile.avatar_path
        profile.avatar_path = None
        _commit_with_retry()
        if old_path and old_path.startswith('avatars/'):
            filepath = os.path.join(_project_root, 'static', old_path)
            if os.path.isfile(filepath):
                try:
                    os.remove(filepath)
                except OSError:
                    pass
        audit_log('avatar_delete', f'user={current_user.username}')
        return _api_ok(data={'avatar_url': None}, message='Profile picture removed')
    except Exception as e:
        logging.exception('api_profile_avatar_delete failed')
        return _api_error(str(e), 500)


@bp.route('/api/ldap/health')
def api_ldap_health():
    """Phase 3.7: LDAP health check - reachable or not."""
    _api_ok, _get_setting = _from_app('_api_ok', '_get_setting')
    ldap_enabled = _get_setting('ldap_enabled', 'false').lower() == 'true'
    if not ldap_enabled:
        return _api_ok(data={'ldap_enabled': False, 'reachable': None, 'message': 'LDAP disabled'})
    ldap_url = _get_setting('ldap_url', '').strip()
    ldap_base_dn = _get_setting('ldap_base_dn', '').strip()
    ldap_bind_dn = _get_setting('ldap_bind_dn', '').strip()
    ldap_bind_password = _get_setting('ldap_bind_password', '').strip()
    reachable, msg = check_ldap_reachable(ldap_url, ldap_base_dn, ldap_bind_dn, ldap_bind_password)
    return _api_ok(data={'ldap_enabled': True, 'reachable': reachable, 'message': msg})


@bp.route('/api/users', methods=['GET'])
@login_required
def api_list_users():
    """List active users (id, username) for Assign-to dropdown in Submit/Edit."""
    (_api_ok,) = _from_app('_api_ok')
    users = User.query.filter(User.is_active == True).order_by(User.username).all()  # noqa: E712
    result = [{'id': u.id, 'username': u.username} for u in users]
    return _api_ok(data={'users': result})


@bp.route('/api/auth/me')
def api_auth_me():
    """Return current user info for frontend (authenticated or anonymous). Phase 4: avatar_url."""
    (_api_ok,) = _from_app('_api_ok')
    if current_user.is_authenticated:
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        avatar = _avatar_url(profile)
        return _api_ok(data={
            'authenticated': True,
            'username': current_user.username,
            'is_admin': current_user.is_admin,
            'display_name': (profile and profile.display_name) or current_user.username,
            'avatar_url': avatar,
        })
    return _api_ok(data={
        'authenticated': False,
        'username': None,
        'is_admin': False,
        'display_name': None,
        'avatar_url': None,
    })
