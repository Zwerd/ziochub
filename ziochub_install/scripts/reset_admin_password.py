#!/usr/bin/env python3
"""
Reset admin user password and set source to 'local'.
Run from project root: python scripts/reset_admin_password.py
Or with custom password: python scripts/reset_admin_password.py --password "YourNewPassword"
"""
import argparse
import os
import sys

# Run from project root so app can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from extensions import db
from models import User
from utils.auth import hash_password


def main():
    parser = argparse.ArgumentParser(description='Reset admin password and set source=local')
    parser.add_argument('--password', '-p', default='admin', help='New password (default: admin)')
    parser.add_argument('--username', '-u', default='admin', help='Username to reset (default: admin)')
    args = parser.parse_args()

    password = args.password.strip()
    username = (args.username or '').strip().lower()
    if not username:
        print('Error: username is required')
        sys.exit(1)
    if len(password) < 4:
        print('Error: password must be at least 4 characters')
        sys.exit(1)

    with app.app_context():
        u = User.query.filter_by(username=username).first()
        if not u:
            print(f'User "{username}" not found in database.')
            sys.exit(1)
        u.password_hash = hash_password(password)
        u.source = 'local'
        u.is_active = True
        db.session.commit()
        print(f'Password and source reset OK for user "{username}". You can now log in with this password.')


if __name__ == '__main__':
    main()
