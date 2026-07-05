#!/usr/bin/env python3
"""
Verify PostgreSQL migration health on an upgraded ZIoCHub server.

Checks:
  - PostgreSQL configured and reachable
  - Legacy ziochub.db archived (not pending migration)
  - SERIAL sequences aligned with MAX(id) on all mapped tables
  - Core tables present with data

Usage:
  cd /opt/ziochub
  set -a && source data/ziochub.env && set +a
  ./venv/bin/python3 scripts/verify_postgres_migration.py

  Prefer user ziochub (matches systemd):
  sudo -u ziochub bash -c 'cd /opt/ziochub && set -a && source data/ziochub.env && set +a && \
    venv/bin/python3 scripts/verify_postgres_migration.py'

Exit 0 = all checks passed; exit 1 = action required.
"""
from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from utils.db_config import ensure_postgresql_env_loaded

DATA_DIR = os.environ.get('ZIOCHUB_DATA_DIR') or os.path.join(BASE_DIR, 'data')
SQLITE_PATH = os.path.join(DATA_DIR, 'ziochub.db')
MIGRATE_LOG = os.path.join(DATA_DIR, 'migrate_sqlite_to_postgres.log')
VENV_PYTHON = os.path.join(BASE_DIR, 'venv', 'bin', 'python3')


def _require_psycopg2() -> None:
    try:
        import psycopg2  # noqa: F401
    except ModuleNotFoundError:
        print('FAIL: psycopg2 is not installed for this Python interpreter.', file=sys.stderr)
        print(f'      Current: {sys.executable}', file=sys.stderr)
        if os.path.isfile(VENV_PYTHON):
            print(f'      Use:     {VENV_PYTHON} scripts/verify_postgres_migration.py', file=sys.stderr)
        print('      Or:      sudo -u ziochub bash -c \'cd /opt/ziochub && set -a && source data/ziochub.env && set +a && venv/bin/python3 scripts/verify_postgres_migration.py\'', file=sys.stderr)
        raise SystemExit(1)


def _fail(msg: str) -> None:
    print(f'FAIL: {msg}')


def _ok(msg: str) -> None:
    print(f'OK:   {msg}')


def _warn(msg: str) -> None:
    print(f'WARN: {msg}')


def _check_sqlite_archived() -> bool:
    if os.path.isfile(SQLITE_PATH):
        _fail(f'Legacy SQLite still present: {SQLITE_PATH} — migration incomplete or re-run pending.')
        return False
    _ok('No pending ziochub.db (migration archived or N/A).')
    archived = sorted(
        f for f in os.listdir(DATA_DIR)
        if f.startswith('ziochub.db.pre_postgresql_')
    ) if os.path.isdir(DATA_DIR) else []
    if archived:
        _ok(f'SQLite archive found: {archived[-1]}')
    return True


def _check_migrate_log() -> bool:
    if not os.path.isfile(MIGRATE_LOG):
        _warn(f'Migration log not found ({MIGRATE_LOG}) — may be a fresh PG install, not SQLite upgrade.')
        return True
    try:
        with open(MIGRATE_LOG, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError as exc:
        _warn(f'Cannot read migration log: {exc}')
        return True
    if 'Migration complete' in text:
        _ok('Migration log reports successful copy.')
    else:
        _fail('Migration log exists but no "Migration complete" line — review the log.')
        return False
    if 'Sequences reset for' in text:
        _ok('Migration log reports sequence reset.')
    elif 'sequence reset failed' in text.lower():
        _fail('Migration log reports sequence reset failure — run fix_postgres_sequences.py')
        return False
    else:
        _warn('Migration log has no sequence-reset line (older installer?) — checking sequences below.')
    return True


def _sequence_issues(session, engine, metadata) -> list[str]:
    from utils.schema_migrations import list_postgres_sequence_issues

    return list_postgres_sequence_issues(session, metadata)


def main() -> int:
    _require_psycopg2()
    os.environ.setdefault('FLASK_APP', 'app')
    env_file = ensure_postgresql_env_loaded(DATA_DIR)
    if not env_file or not os.path.isfile(env_file):
        _fail(f'PostgreSQL env missing: {os.path.join(DATA_DIR, "ziochub.env")} — run setup.sh first.')
        print('Hint: sudo -u ziochub bash -c "cd /opt/ziochub && python3 scripts/verify_postgres_migration.py"')
        return 1
    if env_file:
        _ok(f'Loaded env: {env_file}')

    from app import app, db
    import models  # noqa: F401

    print('ZIoCHub PostgreSQL migration verification')
    print(f'Data dir: {DATA_DIR}')
    print()

    ok = True
    ok = _check_sqlite_archived() and ok
    ok = _check_migrate_log() and ok

    with app.app_context():
        if db.engine.dialect.name != 'postgresql':
            _fail(f'Database backend is {db.engine.dialect.name}, expected postgresql.')
            return 1
        _ok(f'PostgreSQL connected: {db.engine.url.render_as_string(hide_password=True)}')

        try:
            db.session.execute(__import__('sqlalchemy').text('SELECT 1'))
            _ok('SELECT 1 succeeded.')
        except Exception as exc:
            _fail(f'Database query failed: {exc}')
            return 1

        from models import User, IOC
        from sqlalchemy import func

        user_count = db.session.query(func.count(User.id)).scalar() or 0
        ioc_count = db.session.query(func.count(IOC.id)).scalar() or 0
        _ok(f'Row counts: users={user_count}, iocs={ioc_count}')

        issues = _sequence_issues(db.session, db.engine, db.metadata)
        if issues:
            ok = False
            _fail(f'{len(issues)} sequence mismatch(es) — login/insert may fail with duplicate key:')
            for line in issues:
                print(f'      - {line}')
            print()
            print('Fix: cd /opt/ziochub && set -a && source data/ziochub.env && set +a && \\')
            print('  ./venv/bin/python3 scripts/fix_postgres_sequences.py')
        else:
            _ok('All SERIAL sequences aligned with table MAX(id) values.')

    print()
    if ok:
        print('RESULT: PASSED — migration state looks healthy.')
        return 0
    print('RESULT: FAILED — fix issues above before treating migration as complete.')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
