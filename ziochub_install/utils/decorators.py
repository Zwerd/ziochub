"""
Auth decorators: login_required, admin_required, admin_required_page.
"""
from functools import wraps
from flask import jsonify, redirect, url_for, request, render_template

try:
    from flask_login import current_user
    FLASK_LOGIN_AVAILABLE = True
except ImportError:
    FLASK_LOGIN_AVAILABLE = False
    current_user = None


def admin_required_page(f):
    """Require admin for HTML pages. Redirect to login if unauthenticated; render 403 if not admin."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not FLASK_LOGIN_AVAILABLE:
            return f(*args, **kwargs)
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        if not getattr(current_user, 'is_admin', False):
            return render_template('admin/403.html'), 403
        return f(*args, **kwargs)
    return wrapped


def login_required(f):
    """Require authenticated user. Return 401 JSON for API, or redirect for HTML."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not FLASK_LOGIN_AVAILABLE:
            return f(*args, **kwargs)
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Authentication required', 'require_login': True}), 401
        return f(*args, **kwargs)
    return wrapped


def admin_required(f):
    """Require authenticated admin user."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not FLASK_LOGIN_AVAILABLE:
            return f(*args, **kwargs)
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Authentication required', 'require_login': True}), 401
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'success': False, 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return wrapped
