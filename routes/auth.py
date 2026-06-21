"""Auth routes blueprint: login, logout, change-password, profile, LDAP health, users list."""
import json
import logging
import os

from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from flask_login import login_user, logout_user, current_user

from sqlalchemy import func
from extensions import db
from models import User, UserProfile, UserSession, UserNotification, _utcnow
from utils.auth import hash_password, verify_password
from utils.decorators import login_required
from utils.ldap_auth import try_ldap_bind_servers, try_ldap_bind, try_ldap_mock_dev, check_ldap_reachable, is_dev_mode

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
        from utils.audit_events import audit_log_event
        audit_log_event(
            'login_fail',
            'fail',
            username=username or None,
            reason='missing_credentials',
        )
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

    # Phase 2: Try local first when auth_mode is local_only or local_with_ldap_fallback
    # Username lookup is case-insensitive so "Admin" and "admin" both work
    if auth_mode in ('local_only', 'local_with_ldap_fallback'):
        local_user = User.query.filter(func.lower(User.username) == username, User.source == 'local', User.is_active == True).first()
        if local_user and verify_password(local_user.password_hash, password):
            user = local_user
        # Fallback: user may have source='ldap' after a prior LDAP login; if they have a stored hash and it matches, allow local login
        if user is None:
            any_user = User.query.filter(func.lower(User.username) == username, User.is_active == True).first()
            if any_user and any_user.password_hash and verify_password(any_user.password_hash, password):
                user = any_user
                if user.source != 'local':
                    user.source = 'local'
                    _commit_with_retry()
                    logging.info('Login: user %s source reset to local (password matched)', username)

    # Phase 3: Try LDAP if enabled and (user not found yet) and auth_mode allows LDAP
    if user is None and ldap_enabled and auth_mode in ('ldap', 'ldap_with_local_fallback', 'local_with_ldap_fallback'):
        try:
            import json as _json
            ldap_user_filter = _get_setting('ldap_user_filter', '(sAMAccountName=%(user)s)').strip()
            servers = []
            raw_servers = (_get_setting('ldap_servers', '') or '').strip()
            if raw_servers and raw_servers != '[]':
                try:
                    servers = _json.loads(raw_servers)
                except Exception:
                    pass
            if not servers and _get_setting('ldap_url', '').strip():
                servers = [{
                    'url': _get_setting('ldap_url', ''),
                    'base_dn': _get_setting('ldap_base_dn', ''),
                    'bind_dn': _get_setting('ldap_bind_dn', ''),
                    'bind_password': _get_setting('ldap_bind_password', ''),
                }]
            ldap_ok = False
            display_name = None
            if servers:
                ldap_ok, display_name = try_ldap_bind_servers(servers, ldap_user_filter, username, password)
            if not ldap_ok:
                ldap_ok, display_name = try_ldap_mock_dev(username, password)
            if not ldap_ok and servers:
                logging.warning('Phase 6.3: LDAP unreachable for %s (tried %d server(s)); falling back to local if auth_mode allows', username, len(servers))
            if ldap_ok:
                user = User.query.filter(func.lower(User.username) == username).first()
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
                    # Do not overwrite display_name if user already set a custom one in profile
                    if not (profile.display_name or '').strip():
                        profile.display_name = display_name or username
                else:
                    db.session.add(UserProfile(user_id=user.id, display_name=display_name or username))
                _commit_with_retry()
        except Exception as e:
            logging.exception('LDAP login phase failed for %s: %s', username, e)
            # Do not raise: continue so fallback to local can run or we return 401

    # Fallback to local auth only for ldap_with_local_fallback (LDAP was tried first and failed)
    if user is None and auth_mode == 'ldap_with_local_fallback':
        local_user = User.query.filter(func.lower(User.username) == username, User.source == 'local', User.is_active == True).first()
        if local_user and verify_password(local_user.password_hash, password):
            user = local_user
        elif ldap_enabled:
            logging.warning('LDAP auth failed for %s, falling back to local', username)

    if user is None:
        logging.warning('Login failed for username=%s (auth_mode=%s)', username, auth_mode)
        from utils.audit_events import audit_log_event
        audit_log_event(
            'login_fail',
            'fail',
            username=username,
            reason='invalid_credentials',
            auth_mode=auth_mode,
        )
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
        'mute_sound': getattr(profile, 'mute_sound', False) if profile else False,
        'ambition_popup_disabled': getattr(profile, 'ambition_popup_disabled', False) if profile else False,
        'achievement_popup_disabled': getattr(profile, 'achievement_popup_disabled', False) if profile else False,
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
        if 'mute_sound' in data:
            profile.mute_sound = bool(data.get('mute_sound'))
        if 'ambition_popup_disabled' in data:
            profile.ambition_popup_disabled = bool(data.get('ambition_popup_disabled'))
        if 'achievement_popup_disabled' in data:
            profile.achievement_popup_disabled = bool(data.get('achievement_popup_disabled'))
        _commit_with_retry()
        audit_log('profile_update', f'user={current_user.username}')
        return jsonify({
            'success': True,
            'message': 'Profile updated',
            'display_name': profile.display_name,
            'avatar_url': _avatar_url(profile),
            'mute_sound': profile.mute_sound,
            'ambition_popup_disabled': profile.ambition_popup_disabled,
            'achievement_popup_disabled': profile.achievement_popup_disabled,
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
    """Phase 3.7: LDAP health check - reachable or not (uses first configured server)."""
    _api_ok, _get_setting = _from_app('_api_ok', '_get_setting')
    import json as _json
    ldap_enabled = _get_setting('ldap_enabled', 'false').lower() == 'true'
    if not ldap_enabled:
        return _api_ok(data={'ldap_enabled': False, 'reachable': None, 'message': 'LDAP disabled'})
    servers = []
    raw_servers = (_get_setting('ldap_servers', '') or '').strip()
    if raw_servers and raw_servers != '[]':
        try:
            servers = _json.loads(raw_servers)
        except Exception:
            pass
    if not servers and _get_setting('ldap_url', '').strip():
        servers = [{
            'url': _get_setting('ldap_url', ''),
            'base_dn': _get_setting('ldap_base_dn', ''),
            'bind_dn': _get_setting('ldap_bind_dn', ''),
            'bind_password': _get_setting('ldap_bind_password', ''),
        }]
    if not servers:
        return _api_ok(data={'ldap_enabled': True, 'reachable': False, 'message': 'No LDAP servers configured'})
    s = servers[0]
    reachable, msg = check_ldap_reachable(
        (s.get('url') or '').strip(),
        (s.get('base_dn') or '').strip(),
        (s.get('bind_dn') or '').strip(),
        s.get('bind_password') or '',
    )
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
    (_api_ok, _get_setting) = _from_app('_api_ok', '_get_setting')
    from utils.workflow_settings import ui_workflow_flags
    ui = ui_workflow_flags(current_user if current_user.is_authenticated else None, _get_setting)
    if current_user.is_authenticated:
        profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        avatar = _avatar_url(profile)
        return _api_ok(data={
            'authenticated': True,
            'username': current_user.username,
            'is_admin': current_user.is_admin,
            'display_name': (profile and profile.display_name) or current_user.username,
            'avatar_url': avatar,
            'ui': ui,
        })
    return _api_ok(data={
        'authenticated': False,
        'username': None,
        'is_admin': False,
        'display_name': None,
        'avatar_url': None,
        'ui': ui,
    })


@bp.route('/api/inbox', methods=['GET'])
@login_required
def api_user_inbox():
    """Analyst inbox: YARA/tag approval outcomes for the current user."""
    _api_ok, _api_error, _commit_with_retry = _from_app('_api_ok', '_api_error', '_commit_with_retry')
    try:
        from utils.user_notifications import (
            backfill_yara_rejection_notifications,
            notification_to_dict,
        )

        backfill_yara_rejection_notifications(current_user.id, current_user.username)
        _commit_with_retry()

        unread_count = UserNotification.query.filter_by(
            user_id=current_user.id,
        ).filter(UserNotification.read_at.is_(None)).count()

        rows = (
            UserNotification.query.filter_by(user_id=current_user.id)
            .order_by(UserNotification.created_at.desc())
            .limit(50)
            .all()
        )
        return _api_ok(data={
            'unread_count': unread_count,
            'notifications': [notification_to_dict(r) for r in rows],
        })
    except Exception as e:
        logging.exception('api_user_inbox failed')
        return _api_error(str(e), 500)


@bp.route('/api/inbox/mark-read', methods=['POST'])
@login_required
def api_user_inbox_mark_read():
    """Mark inbox notification(s) as read. Body: { ids: [1,2] } or { all: true }."""
    _api_ok, _api_error, _commit_with_retry = _from_app('_api_ok', '_api_error', '_commit_with_retry')
    try:
        from utils.user_notifications import mark_yara_rejection_seen_for_user

        data = request.get_json(silent=True) or {}
        mark_all = bool(data.get('all'))
        ids = data.get('ids') or []
        if isinstance(ids, (int, str)):
            ids = [ids]
        ids = [int(x) for x in ids if str(x).strip().isdigit()]

        now = _utcnow()
        q = UserNotification.query.filter_by(user_id=current_user.id).filter(
            UserNotification.read_at.is_(None)
        )
        if not mark_all:
            if not ids:
                return jsonify({'success': False, 'message': 'Missing ids or all=true'}), 400
            q = q.filter(UserNotification.id.in_(ids))

        updated = 0
        yara_filenames = []
        for row in q.all():
            row.read_at = now
            updated += 1
            if row.category == 'yara' and row.outcome == 'rejected':
                try:
                    payload = json.loads(row.payload or '{}')
                except (TypeError, ValueError):
                    payload = {}
                fn = (payload.get('filename') or '').strip()
                if fn:
                    yara_filenames.append(fn)

        if mark_all:
            mark_yara_rejection_seen_for_user(current_user.id, current_user.username)
        else:
            for fn in yara_filenames:
                mark_yara_rejection_seen_for_user(current_user.id, current_user.username, filename=fn)

        _commit_with_retry()
        return _api_ok(data={'updated': updated}, message='Marked as read')
    except Exception as e:
        db.session.rollback()
        logging.exception('api_user_inbox_mark_read failed')
        return _api_error(str(e), 500)
