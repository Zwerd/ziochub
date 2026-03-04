#!/usr/bin/env python3
"""
ThreatGate - Lab Users Setup Script
====================================
Creates the lab analyst team from users/users.json.
Prompts for a single password that will be set for ALL users.

Usage:
    python create_lab_users.py                # interactive - asks for password
    python create_lab_users.py --password P@ss  # non-interactive

Users are defined in users/users.json. Each user can have:
  - username, display_name, is_admin
  - role (short title)
  - description (role_description in profile)
  - image (filename in users/ folder → copied to static/avatars/)

NOTE: Stop the ThreatGate service before running, or run while service is
      stopped to avoid session issues:
          sudo systemctl stop threatgate
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

# --- resolve paths (same logic as app.py) ---
_base_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = (_config and _config.DATA_DIR) or os.path.join(_base_dir, 'data')
_db_path = (_config and getattr(_config, 'DB_PATH', None)) or os.path.join(_data_dir, 'threatgate.db')
_users_dir = os.path.join(_base_dir, 'users')
_users_json = os.path.join(_users_dir, 'users.json')
_avatars_dir = os.path.join(_base_dir, 'static', 'avatars')
ALLOWED_AVATAR_EXT = frozenset({'jpg', 'jpeg', 'png', 'gif', 'webp'})

# --- hash helper (werkzeug scrypt, same as utils/auth.py) ---
try:
    from werkzeug.security import generate_password_hash
except ImportError:
    print("ERROR: werkzeug is not installed. Activate the venv first:")
    print("  source /opt/threatgate/venv/bin/activate")
    sys.exit(1)

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


def create_users(db_path, password, users_list):
    pw_hash = generate_password_hash(password, method='scrypt')
    conn = sqlite3.connect(db_path)
    now = utcnow_str()

    created = 0
    updated = 0

    # Reset admin password (admin user must already exist from app startup)
    admin_row = conn.execute(
        "SELECT id FROM users WHERE username = 'admin'", ()
    ).fetchone()
    if admin_row:
        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
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
                    "INSERT INTO user_profiles (user_id, display_name, role_description, avatar_path) VALUES (?, ?, ?, ?)",
                    (admin_id, disp, desc, avatar_path),
                )
        else:
            prof = conn.execute("SELECT id FROM user_profiles WHERE user_id = ?", (admin_id,)).fetchone()
            if prof:
                conn.execute("UPDATE user_profiles SET display_name = ? WHERE user_id = ?", ('Administrator', admin_id))
            else:
                conn.execute("INSERT INTO user_profiles (user_id, display_name) VALUES (?, ?)", (admin_id, 'Administrator'))
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
            conn.execute(
                "UPDATE users SET password_hash = ?, is_admin = ?, is_active = 1, updated_at = ? WHERE id = ?",
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
                    "INSERT INTO user_profiles (user_id, display_name, role_description, avatar_path) VALUES (?, ?, ?, ?)",
                    (user_id, display_name, description, avatar_path),
                )
            updated += 1
            print(f"  {c('~', 'yellow')} {username:<12} {display_name:<22} {'Admin' if is_admin else '-':<6}  (updated)")
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, source, is_admin, is_active, created_at, updated_at) "
                "VALUES (?, ?, 'local', ?, 1, ?, ?)",
                (username, pw_hash, int(is_admin), now, now),
            )
            user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            avatar_path = copy_avatar_to_static(image, user_id, username)
            conn.execute(
                "INSERT INTO user_profiles (user_id, display_name, role_description, avatar_path) VALUES (?, ?, ?, ?)",
                (user_id, display_name, description, avatar_path),
            )
            created += 1
            print(f"  {c('+', 'green')} {username:<12} {display_name:<22} {'Admin' if is_admin else '-':<6}  (created)")

    conn.commit()
    conn.close()
    return created, updated


def main():
    parser = argparse.ArgumentParser(description='ThreatGate - Create lab users from users/users.json')
    parser.add_argument('--password', '-p', help='Password for all users (prompted if omitted)')
    args = parser.parse_args()

    print(f"\n{c('=== ThreatGate Lab Users Setup ===', 'bold')}")
    print(f"  Database: {_db_path}")
    print(f"  Users:    {_users_json}")

    if not os.path.exists(_db_path):
        print(f"\n  {c('ERROR:', 'red')} Database not found at {_db_path}")
        print(f"  Run the app once first to initialize the DB.")
        sys.exit(1)

    users_list = load_users_from_json()
    if users_list is None:
        print(f"\n  {c('ERROR:', 'red')} users/users.json not found.")
        print(f"  Create users/users.json with your lab users (see users/README.md).")
        sys.exit(1)

    password = args.password
    if not password:
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

    print(f"\n  {c('Users to create/update:', 'bold')}\n")
    print(f"  {'Username':<12} {'Display Name':<22} {'Role':<6}")
    print(f"  {'─'*12} {'─'*22} {'─'*6}")

    created, updated = create_users(_db_path, password, users_list)

    print(f"\n  {c('Done!', 'green')} Created: {created}, Updated: {updated}")
    print(f"  All users share the same password.\n")


if __name__ == '__main__':
    main()
