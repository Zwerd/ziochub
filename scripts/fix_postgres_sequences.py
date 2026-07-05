#!/usr/bin/env python3
"""
Fix PostgreSQL SERIAL sequences after SQLite→PG migration (or manual data import).

Symptom: IntegrityError duplicate key on INSERT (e.g. user_sessions_pkey id=2).
Cause: rows copied with explicit ids but sequence not advanced.

Usage (production):
  cd /opt/ziochub && set -a && source data/ziochub.env && set +a && \
    ./venv/bin/python3 scripts/fix_postgres_sequences.py
"""
from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

DATA_DIR = os.environ.get('ZIOCHUB_DATA_DIR') or os.path.join(BASE_DIR, 'data')
VENV_PYTHON = os.path.join(BASE_DIR, 'venv', 'bin', 'python3')


def _require_psycopg2() -> None:
    try:
        import psycopg2  # noqa: F401
    except ModuleNotFoundError:
        print('ERROR: psycopg2 not found — use ./venv/bin/python3 (not system python3)', file=sys.stderr)
        if os.path.isfile(VENV_PYTHON):
            print(f'  {VENV_PYTHON} scripts/fix_postgres_sequences.py', file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    _require_psycopg2()
    os.environ.setdefault('FLASK_APP', 'app')
    from utils.db_config import ensure_postgresql_env_loaded

    if not ensure_postgresql_env_loaded(DATA_DIR):
        print(f'ERROR: missing {os.path.join(DATA_DIR, "ziochub.env")}', file=sys.stderr)
        return 1
    from app import app, db
    import models  # noqa: F401
    from utils.schema_migrations import reset_all_postgres_sequences, list_postgres_sequence_issues

    with app.app_context():
        if db.engine.dialect.name != 'postgresql':
            print('ERROR: target database is not PostgreSQL', file=sys.stderr)
            return 1
        before = list_postgres_sequence_issues(db.session, db.metadata)
        if before:
            print(f'Found {len(before)} misaligned sequence(s) before fix:')
            for line in before:
                print(f'  {line}')
        db.session.rollback()
        tables = reset_all_postgres_sequences(db.session, db.metadata)
        print(f'OK — sequences reset for {len(tables)} table(s).')
        for name in tables:
            print(f'  {name}')
        if before and not tables:
            print('ERROR: misaligned sequences detected but none were reset.', file=sys.stderr)
            return 1
        after = list_postgres_sequence_issues(db.session, db.metadata)
        if after:
            print(f'ERROR: {len(after)} sequence(s) still misaligned:', file=sys.stderr)
            for line in after:
                print(f'  {line}', file=sys.stderr)
            return 1
        if before:
            print('All PostgreSQL sequences are now aligned.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
