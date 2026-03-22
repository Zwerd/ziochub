#!/usr/bin/env python3
"""
ZIoCHub - Lab / Production Users Setup Script
=============================================
Creates or updates users from users/users.json. Two modes:
  1) Local: writes directly to SQLite (dev or prod paths). Stop the service first on the server.
  2) Remote: uses the ZIoCHub API over HTTPS (e.g. https://server:8443) to create/update users.

Use --help for all options.
"""

import argparse
import getpass
import json
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone

try:
    import config as _config
except ImportError:
    _config = None

# --- resolve paths (same logic as app.py); overridden in main() when --env prod ---
_base_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = (_config and getattr(_config, 'DATA_DIR', None)) or os.path.join(_base_dir, 'data')
_db_path = (_config and getattr(_config, 'DB_PATH', None)) or os.path.join(_data_dir, 'ziochub.db')
_users_dir = os.path.join(_base_dir, 'users')
_users_json = os.path.join(_users_dir, 'users.json')
_avatars_dir = os.path.join(_base_dir, 'static', 'avatars')
ALLOWED_AVATAR_EXT = frozenset({'jpg', 'jpeg', 'png', 'gif', 'webp'})

# --- hash helper (werkzeug scrypt, same as utils/auth.py) ---
try:
    from werkzeug.security import generate_password_hash
except ImportError:
    print("ERROR: werkzeug is not installed. Activate the venv first:")
    print("  source /opt/ziochub/venv/bin/activate")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None  # only needed for --url (remote) mode

COLORS = {
    'green': '\033[92m',
    'yellow': '\033[93m',
    'red': '\033[91m',
    'cyan': '\033[96m',
    'bold': '\033[1m',
    'reset': '\033[0m',
}


def c(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def load_users_from_json():
    """Load users from users/users.json. Returns list of dicts or None if file missing."""
    if not os.path.isfile(_users_json):
        return None
    try:
        with open(_users_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            print(f"  {c('ERROR:', 'red')} users.json must be a JSON array of user objects.")
            sys.exit(1)
        return data
    except json.JSONDecodeError as e:
        print(f"  {c('ERROR:', 'red')} Invalid JSON in users.json: {e}")
        sys.exit(1)


def copy_avatar_to_static(image_filename, user_id, username=None):
    """
    Copy users/{image_filename} to static/avatars/{user_id}.{ext}.
    Returns avatar_path (e.g. 'avatars/5.jpg') or None on failure.
    If image_filename not found, tries username.{jpg,png,jpeg,gif,webp}.
    """
    candidates = []
    if image_filename and image_filename.strip():
        candidates.append(image_filename.strip())
    if username:
        for ext in ('jpg', 'jpeg', 'png', 'gif', 'webp'):
            candidates.append(f"{username}.{ext}")
    found = None
    for fn in candidates:
        p = os.path.join(_users_dir, fn)
        if os.path.isfile(p):
            found = fn
            break
    if not found:
        return None
    ext = (found.rsplit('.', 1)[-1] or '').lower()
    if ext not in ALLOWED_AVATAR_EXT:
        return None
    safe_ext = 'jpg' if ext in ('jpg', 'jpeg') else ext
    os.makedirs(_avatars_dir, exist_ok=True)
    dest_filename = f"{user_id}.{safe_ext}"
    dest_path = os.path.join(_avatars_dir, dest_filename)
    shutil.copy2(os.path.join(_users_dir, found), dest_path)
    return f"avatars/{dest_filename}"


def utcnow_str():
    return datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')


def _ensure_champ_scores_rows(conn, user_ids, now):
    """Ensure champ_scores has a row for each user (0 points) so they appear on the leaderboard."""
    if not user_ids:
        return
    try:
        for uid in user_ids:
            conn.execute(
                "INSERT OR REPLACE INTO champ_scores (user_id, score, total_iocs, yara_count, deletion_count, streak_days, last_activity, updated_at) "
                "VALUES (?, 0, 0, 0, 0, 0, NULL, ?)",
                (uid, now),
            )
    except sqlite3.OperationalError:
        pass  # champ_scores table may not exist yet (run app once to create)


def run_remote(base_url: str, admin_user: str, admin_password: str, password: str, users_list: list, insecure: bool) -> tuple:
    """Create/update users via ZIoCHub API (HTTPS). Returns (created_count, updated_count)."""
    if not requests:
        print("  ERROR: 'requests' is required for remote mode. Install: pip install requests")
        return 0, 0
    base_url = base_url.rstrip('/')
    session = requests.Session()
    session.verify = not insecure
    session.headers.update({'Accept': 'application/json'})

    # Login (form POST); app redirects to index on success
    login_url = f"{base_url}/login"
    r = session.post(login_url, data={'username': admin_user, 'password': admin_password}, timeout=30, allow_redirects=True)
    if r.status_code != 200:
        print(f"  ERROR: Login failed. Status: {r.status_code}")
        return 0, 0
    if 'login' in (r.url or '') or (r.text and 'Invalid username' in r.text):
        print("  ERROR: Invalid admin credentials.")
        return 0, 0

    # List existing users
    list_url = f"{base_url}/api/admin/users"
    r = session.get(list_url, timeout=30)
    if r.status_code != 200:
        print(f"  ERROR: GET /api/admin/users failed: {r.status_code}")
        return 0, 0
    try:
        data = r.json()
    except Exception:
        print("  ERROR: Invalid JSON from /api/admin/users")
        return 0, 0
    payload = data.get('data') or data
    existing = {str(u.get('username', '')).lower(): u for u in (payload.get('users') or payload if isinstance(payload, list) else []) if u.get('username')}

    created = 0
    updated = 0
    for u in users_list:
        username = (u.get('username') or '').strip()
        if not username or username.lower() == 'admin':
            continue
        display_name = (u.get('display_name') or username).strip()
        is_admin = bool(u.get('is_admin', False))
        key = username.lower()
        if key in existing:
            user_id = existing[key].get('id')
            if user_id is None:
                continue
            put_url = f"{base_url}/api/admin/users/{user_id}"
            r = session.put(put_url, json={'display_name': display_name, 'is_admin': is_admin, 'password': password}, timeout=30)
            if r.status_code == 200:
                updated += 1
                print(f"  {c('~', 'yellow')} {username:<12} {display_name:<22} {'Admin' if is_admin else '-':<6}  (updated)")
            else:
                print(f"  {c('Failed', 'red')}   {username} PUT: {r.status_code} {r.text[:80]}")
        else:
            r = session.post(list_url, json={'username': username, 'password': password, 'display_name': display_name, 'is_admin': is_admin}, timeout=30)
            if r.status_code in (200, 201):
                created += 1
                print(f"  {c('+', 'green')} {username:<12} {display_name:<22} {'Admin' if is_admin else '-':<6}  (created)")
            else:
                print(f"  {c('Failed', 'red')}   {username} POST: {r.status_code} {r.text[:80]}")
    return created, updated


def create_users(db_path, password, users_list):
    pw_hash = generate_password_hash(password, method='scrypt')
    conn = sqlite3.connect(db_path)
    now = utcnow_str()

    created = 0
    updated = 0
    touched_user_ids = []

    # Reset admin password (admin user must already exist from app startup)
    admin_row = conn.execute(
        "SELECT id FROM users WHERE username = 'admin'", ()
    ).fetchone()
    if admin_row:
        touched_user_ids.append(admin_row[0])
        conn.execute(
            "UPDATE users SET password_hash = ?, source = 'local', must_change_password = 0, updated_at = ? WHERE id = ?",
            (pw_hash, now, admin_row[0]),
        )
        updated += 1
        # If admin is in users_list, update profile (avatar, description)
        admin_entry = next((u for u in users_list if u.get('username') == 'admin'), None)
        admin_id = admin_row[0]
        if admin_entry:
            avatar_path = copy_avatar_to_static(admin_entry.get('image'), admin_id, admin_entry.get('username'))
            desc = admin_entry.get('description') or ''
            disp = admin_entry.get('display_name') or 'Administrator'
            prof = conn.execute("SELECT id FROM user_profiles WHERE user_id = ?", (admin_id,)).fetchone()
            if prof:
                conn.execute(
                    "UPDATE user_profiles SET display_name = ?, role_description = ?, avatar_path = COALESCE(?, avatar_path) WHERE user_id = ?",
                    (disp, desc, avatar_path, admin_id),
                )
            else:
                conn.execute(
                    "INSERT INTO user_profiles (user_id, display_name, role_description, avatar_path, mute_sound, ambition_popup_disabled, achievement_popup_disabled) VALUES (?, ?, ?, ?, 0, 0, 0)",
                    (admin_id, disp, desc, avatar_path),
                )
        else:
            prof = conn.execute("SELECT id FROM user_profiles WHERE user_id = ?", (admin_id,)).fetchone()
            if prof:
                conn.execute("UPDATE user_profiles SET display_name = ? WHERE user_id = ?", ('Administrator', admin_id))
            else:
                conn.execute(
                    "INSERT INTO user_profiles (user_id, display_name, mute_sound, ambition_popup_disabled, achievement_popup_disabled) VALUES (?, ?, 0, 0, 0)",
                    (admin_id, 'Administrator'),
                )
        print(f"  {c('~', 'yellow')} {'admin':<12} {'Administrator':<22} {'Admin':<6}  (password reset)")
    else:
        print(f"  {c('!', 'red')} {'admin':<12} {'Administrator':<22} {'Admin':<6}  (NOT FOUND — run the app once first)")

    # Create or update lab users (skip admin - already handled)
    for u in users_list:
        username = (u.get('username') or '').strip()
        if not username or username == 'admin':
            continue
        display_name = (u.get('display_name') or username).strip()
        is_admin = bool(u.get('is_admin', False))
        description = (u.get('description') or '').strip() or None
        image = u.get('image')

        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if row:
            user_id = row[0]
            touched_user_ids.append(user_id)
            conn.execute(
                "UPDATE users SET password_hash = ?, source = 'local', is_admin = ?, is_active = 1, must_change_password = 0, updated_at = ? WHERE id = ?",
                (pw_hash, int(is_admin), now, user_id),
            )
            avatar_path = copy_avatar_to_static(image, user_id, username)
            profile = conn.execute(
                "SELECT id FROM user_profiles WHERE user_id = ?", (user_id,)
            ).fetchone()
            if profile:
                conn.execute(
                    "UPDATE user_profiles SET display_name = ?, role_description = ?, avatar_path = COALESCE(?, avatar_path) WHERE user_id = ?",
                    (display_name, description, avatar_path, user_id),
                )
            else:
                conn.execute(
                    "INSERT INTO user_profiles (user_id, display_name, role_description, avatar_path, mute_sound, ambition_popup_disabled, achievement_popup_disabled) VALUES (?, ?, ?, ?, 0, 0, 0)",
                    (user_id, display_name, description, avatar_path),
                )
            updated += 1
            print(f"  {c('~', 'yellow')} {username:<12} {display_name:<22} {'Admin' if is_admin else '-':<6}  (updated)")
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, source, is_admin, is_active, must_change_password, created_at, updated_at) "
                "VALUES (?, ?, 'local', ?, 1, 0, ?, ?)",
                (username, pw_hash, int(is_admin), now, now),
            )
            user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            avatar_path = copy_avatar_to_static(image, user_id, username)
            conn.execute(
                "INSERT INTO user_profiles (user_id, display_name, role_description, avatar_path, mute_sound, ambition_popup_disabled, achievement_popup_disabled) VALUES (?, ?, ?, ?, 0, 0, 0)",
                (user_id, display_name, description, avatar_path),
            )
            touched_user_ids.append(user_id)
            created += 1
            print(f"  {c('+', 'green')} {username:<12} {display_name:<22} {'Admin' if is_admin else '-':<6}  (created)")

    _ensure_champ_scores_rows(conn, touched_user_ids, now)
    conn.commit()
    conn.close()
    return created, updated


def main():
    global _base_dir, _data_dir, _db_path, _users_dir, _users_json, _avatars_dir
    parser = argparse.ArgumentParser(
        description='ZIoCHub - Create or update users from users/users.json (local DB or remote API).',
        epilog="""
Examples:
  Local (development, port 5000):
    python create_lab_users.py
    python create_lab_users.py --env dev

  Local (production on server, /opt/ziochub):
    sudo systemctl stop ziochub
    python create_lab_users.py --env prod
    sudo systemctl start ziochub

  Remote (production over HTTPS, e.g. port 8443):
    python create_lab_users.py --url https://server:8443 --admin-user admin
    python create_lab_users.py --url https://server:8443 --admin-user admin --insecure

Passwords are always prompted (never pass via CLI, to avoid shell history).
"""
    )
    parser.add_argument('--env', choices=('dev', 'prod'), default='dev',
                        help='Local mode: dev = script dir + ./data (port 5000); prod = /opt/ziochub. Default: dev')
    parser.add_argument('--url', metavar='BASE_URL', default=None,
                        help='Remote mode: ZIoCHub base URL (e.g. https://host:8443). Creates/updates users via API.')
    parser.add_argument('--admin-user', metavar='USER', default=None,
                        help='Admin username for remote mode (required when using --url)')
    parser.add_argument('--insecure', action='store_true',
                        help='Skip TLS certificate verification (remote mode only)')
    args = parser.parse_args()

    remote = bool(args.url)
    if remote:
        _base_dir = os.path.dirname(os.path.abspath(__file__))
        _data_dir = os.path.join(_base_dir, 'data')
        _db_path = os.path.join(_data_dir, 'ziochub.db')  # unused in remote
        _users_dir = os.path.join(_base_dir, 'users')
        _users_json = os.path.join(_users_dir, 'users.json')
        _avatars_dir = os.path.join(_base_dir, 'static', 'avatars')
        if not args.admin_user:
            print("  ERROR: --admin-user is required when using --url")
            sys.exit(1)
    elif args.env == 'prod':
        _base_dir = '/opt/ziochub'
        _data_dir = os.path.join(_base_dir, 'data')
        _db_path = os.path.join(_data_dir, 'ziochub.db')
        _users_dir = os.path.join(_base_dir, 'users')
        _users_json = os.path.join(_users_dir, 'users.json')
        _avatars_dir = os.path.join(_base_dir, 'static', 'avatars')
    # else dev: already set at top level

    print(f"\n{c('=== ZIoCHub Lab Users Setup ===', 'bold')}")
    if remote:
        print(f"  Mode:     remote (API)")
        print(f"  URL:      {args.url}")
        print(f"  Users:    {_users_json}")
    else:
        print(f"  Env:      {args.env} ({'production /opt/ziochub' if args.env == 'prod' else 'development / port 5000'})")
        print(f"  Database: {_db_path}")
        print(f"  Users:    {_users_json}")

    if not remote and not os.path.exists(_db_path):
        print(f"\n  {c('ERROR:', 'red')} Database not found at {_db_path}")
        print(f"  Run the app once first to initialize the DB.")
        sys.exit(1)

    users_list = load_users_from_json()
    if users_list is None:
        print(f"\n  {c('ERROR:', 'red')} users/users.json not found at {_users_json}")
        if args.env == 'prod' and not remote:
            print(f"  For production, create /opt/ziochub/users/ and add users.json there (or copy from dev).")
        else:
            print(f"  Create users/users.json with your lab users (see users/README.md).")
        sys.exit(1)

    # Passwords always via prompt (never CLI) to avoid shell history
    password = getpass.getpass(f"\n  Enter password for all lab users: ")
    if not password:
        print(f"  {c('ERROR:', 'red')} Password cannot be empty.")
        sys.exit(1)
    confirm = getpass.getpass(f"  Confirm password: ")
    if password != confirm:
        print(f"  {c('ERROR:', 'red')} Passwords do not match.")
        sys.exit(1)
    if len(password) < 4:
        print(f"  {c('ERROR:', 'red')} Password must be at least 4 characters.")
        sys.exit(1)

    admin_password = None
    if remote:
        admin_password = getpass.getpass(f"  Enter admin password for {args.admin_user}: ")
        if not admin_password:
            print(f"  {c('ERROR:', 'red')} Admin password cannot be empty.")
            sys.exit(1)

    print(f"\n  {c('Users to create/update:', 'bold')}\n")
    print(f"  {'Username':<12} {'Display Name':<22} {'Role':<6}")
    print(f"  {'─'*12} {'─'*22} {'─'*6}")

    if remote:
        created, updated = run_remote(args.url, args.admin_user, admin_password, password, users_list, args.insecure)
    else:
        created, updated = create_users(_db_path, password, users_list)

    print(f"\n  {c('Done!', 'green')} Created: {created}, Updated: {updated}")
    print(f"  All users share the same password.\n")


if __name__ == '__main__':
    main()
