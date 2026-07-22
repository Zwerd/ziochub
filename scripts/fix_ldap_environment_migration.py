#!/usr/bin/env python3
"""
ZIoCHub - LDAP multi-domain migration repair
============================================

Fixes common post-upgrade issues after adding ldap_environment:
  1. Drops legacy unique index users_username_key (username only).
  2. Re-homes LDAP users stuck on ldap_environment='Default' to configured env names.
  3. Prints diagnostics before/after.

Safe by default: dry-run unless --apply is passed.

Usage (on PROD, from app root e.g. /opt/ziochub):
  sudo -u ziochub ./venv/bin/python scripts/fix_ldap_environment_migration.py
  sudo -u ziochub ./venv/bin/python scripts/fix_ldap_environment_migration.py --apply
  sudo -u ziochub ./venv/bin/python scripts/fix_ldap_environment_migration.py --apply --username guyzw

Stop is not required, but restart ziochub after --apply is recommended.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _base_dir not in sys.path:
    sys.path.insert(0, _base_dir)

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from utils.db_config import build_database_url


def _section(title: str) -> None:
    print()
    print('=' * 72)
    print(title)
    print('=' * 72)


def _rows(result) -> list[dict]:
    return [dict(row._mapping) for row in result]


def _print_table(rows: list[dict], empty_msg: str = '(no rows)') -> None:
    if not rows:
        print(empty_msg)
        return
    cols = list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r.get(c, '') or '')) for r in rows)) for c in cols}
    header = ' | '.join(c.ljust(widths[c]) for c in cols)
    print(header)
    print('-' * len(header))
    for row in rows:
        print(' | '.join(str(row.get(c, '') or '').ljust(widths[c]) for c in cols))


def _fetch_all(conn, sql: str, **params) -> list[dict]:
    return _rows(conn.execute(text(sql), params))


def _load_ldap_environment_names(conn) -> list[str]:
    rows = _fetch_all(
        conn,
        "SELECT key, value FROM system_settings WHERE key IN ('ldap_environments', 'ldap_servers')",
    )
    by_key = {r['key']: (r['value'] or '').strip() for r in rows}
    raw = by_key.get('ldap_environments', '')
    if raw and raw not in ('[]', '{}'):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = []
        if isinstance(data, list):
            names = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                name = (item.get('name') or '').strip()
                if name:
                    names.append(name)
            if names:
                default_first = sorted(
                    names,
                    key=lambda n: not any(
                        isinstance(item, dict) and (item.get('name') or '').strip() == n and item.get('is_default')
                        for item in data
                    ),
                )
                return default_first
    return []


def _default_target_env(conn, explicit: str | None) -> str | None:
    if explicit:
        return explicit.strip()
    names = _load_ldap_environment_names(conn)
    if names:
        return names[0]
    return None


def diagnose(conn, username: str | None) -> None:
    _section('Users (LDAP + ldap_environment)')
    if username:
        users = _fetch_all(
            conn,
            """
            SELECT u.id, u.username, u.source, u.ldap_environment, u.is_admin, u.is_active,
                   u.last_login_at, p.display_name, p.avatar_path
            FROM users u
            LEFT JOIN user_profiles p ON p.user_id = u.id
            WHERE lower(u.username) = lower(:username)
            ORDER BY u.id
            """,
            username=username,
        )
    else:
        users = _fetch_all(
            conn,
            """
            SELECT u.id, u.username, u.source, u.ldap_environment, u.is_admin, u.is_active,
                   u.last_login_at, p.display_name, p.avatar_path
            FROM users u
            LEFT JOIN user_profiles p ON p.user_id = u.id
            WHERE u.source = 'ldap'
            ORDER BY lower(u.username), u.ldap_environment, u.id
            """,
        )
    _print_table(users)

    _section('Indexes on users')
    indexes = _fetch_all(
        conn,
        "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'users' ORDER BY indexname",
    )
    _print_table(indexes)

    _section('LDAP-related system_settings')
    settings = _fetch_all(
        conn,
        """
        SELECT key, left(value, 400) AS value_preview
        FROM system_settings
        WHERE key LIKE 'ldap%' OR key IN ('auth_mode', 'ldap_enabled')
        ORDER BY key
        """,
    )
    _print_table(settings, empty_msg='(no ldap* keys in system_settings)')

    env_names = _load_ldap_environment_names(conn)
    print()
    print(f'Parsed ldap environment names: {env_names or "(none — pass --target-env DOM1)"}')

    if username:
        _section(f'Recent sessions for {username}')
        sessions = _fetch_all(
            conn,
            """
            SELECT us.id, us.user_id, us.login_at, us.logout_at, us.ip_address
            FROM user_sessions us
            JOIN users u ON u.id = us.user_id
            WHERE lower(u.username) = lower(:username)
            ORDER BY us.login_at DESC
            LIMIT 10
            """,
            username=username,
        )
        _print_table(sessions)

    legacy_default = _fetch_all(
        conn,
        "SELECT id, username, ldap_environment FROM users WHERE source = 'ldap' AND ldap_environment = 'Default' ORDER BY id",
    )
    if legacy_default:
        _section("LDAP users still on ldap_environment='Default'")
        _print_table(legacy_default)


def apply_fixes(conn, *, username: str | None, target_env: str, drop_legacy_index: bool) -> dict:
    report: dict = {'changes': [], 'skipped': [], 'errors': []}

    has_legacy_index = _fetch_all(
        conn,
        "SELECT 1 FROM pg_indexes WHERE tablename = 'users' AND indexname = 'users_username_key' LIMIT 1",
    )
    if drop_legacy_index:
        if has_legacy_index:
            conn.execute(text('DROP INDEX IF EXISTS users_username_key'))
            report['changes'].append('Dropped index users_username_key')
        else:
            report['skipped'].append('Index users_username_key not present')
    else:
        report['skipped'].append('Skipped dropping users_username_key (--no-drop-index)')

    where_user = ''
    params: dict = {'target_env': target_env}
    if username:
        where_user = ' AND lower(username) = lower(:username)'
        params['username'] = username

    candidates = _fetch_all(
        conn,
        f"""
        SELECT id, username, ldap_environment
        FROM users
        WHERE source = 'ldap' AND ldap_environment = 'Default' {where_user}
        ORDER BY id
        """,
        **params,
    )

    for row in candidates:
        uid = row['id']
        uname = row['username']
        conflict = _fetch_all(
            conn,
            """
            SELECT id FROM users
            WHERE lower(username) = lower(:username)
              AND ldap_environment = :target_env
              AND id <> :uid
            LIMIT 1
            """,
            username=uname,
            target_env=target_env,
            uid=uid,
        )
        if conflict:
            report['errors'].append(
                f"User id={uid} ({uname}): target env '{target_env}' already taken by id={conflict[0]['id']}; merge manually"
            )
            continue
        conn.execute(
            text(
                """
                UPDATE users
                SET ldap_environment = :target_env
                WHERE id = :uid AND source = 'ldap' AND ldap_environment = 'Default'
                """
            ),
            target_env=target_env,
            uid=uid,
        )
        report['changes'].append(f"Updated user id={uid} ({uname}): Default -> {target_env}")

    if not candidates:
        scope = f"username={username}" if username else 'all LDAP users'
        report['skipped'].append(f"No Default LDAP users to update ({scope})")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description='Repair LDAP ldap_environment migration on PostgreSQL')
    parser.add_argument('--apply', action='store_true', help='Apply changes (default: dry-run only)')
    parser.add_argument('--username', default='guyzw', help='Limit re-home to username (default: guyzw)')
    parser.add_argument('--all-users', action='store_true', help='Re-home all Default LDAP users')
    parser.add_argument('--target-env', default='', help='Target env name (default: from settings or DOM1)')
    parser.add_argument('--no-drop-index', action='store_true', help='Do not drop users_username_key')
    args = parser.parse_args()

    data_dir = os.path.join(_base_dir, 'data')
    db_uri, backend = build_database_url(data_directory=data_dir)
    if backend != 'postgresql':
        print(f'ERROR: Requires PostgreSQL (got {backend}).', file=sys.stderr)
        return 1

    engine = create_engine(db_uri, future=True)

    print('ZIoCHub LDAP environment migration repair')
    print(f'Time: {datetime.now().isoformat(timespec="seconds")}')
    print(f'Mode: {"APPLY" if args.apply else "DRY-RUN (pass --apply to write)"}')

    username_filter = None if args.all_users else (args.username or None)

    with engine.connect() as conn:
        diagnose(conn, username_filter)
        target_env = args.target_env.strip() or _default_target_env(conn, None) or 'DOM1'
        _section('Planned fixes' if args.apply else 'Planned fixes (dry-run)')
        print(f'Target ldap_environment: {target_env}')
        print(f'Drop users_username_key: {not args.no_drop_index}')
        print(f'User scope: {"all Default LDAP users" if args.all_users else username_filter or "all"}')

        if not args.apply:
            print()
            print('Dry-run only — no changes written. Re-run with --apply to execute.')
            return 0

        trans = conn.begin()
        try:
            report = apply_fixes(
                conn,
                username=username_filter,
                target_env=target_env,
                drop_legacy_index=not args.no_drop_index,
            )
            trans.commit()
        except Exception as exc:
            trans.rollback()
            print(f'ERROR: rolled back: {exc}', file=sys.stderr)
            return 1

        _section('Apply report')
        for line in report['changes']:
            print(f'  [OK] {line}')
        for line in report['skipped']:
            print(f'  [skip] {line}')
        for line in report['errors']:
            print(f'  [ERR] {line}')

        if report['errors']:
            return 2

        diagnose(conn, username_filter)

    print()
    print('Done. Recommended: sudo systemctl restart ziochub')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
