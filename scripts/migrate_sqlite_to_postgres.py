#!/usr/bin/env python3
"""
ZIoCHub — full migration from legacy SQLite (ziochub.db) to PostgreSQL.

Run by setup.sh on --upgrade when ziochub.db exists and PostgreSQL is configured.
Requires ZIOCHUB_DATABASE_URL (or ZIOCHUB_PG_*) in the environment.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)


def _parse_args():
    p = argparse.ArgumentParser(description='Migrate ZIoCHub SQLite database to PostgreSQL')
    p.add_argument('--sqlite-path', required=True, help='Path to legacy ziochub.db')
    p.add_argument('--data-dir', default='', help='ZIoCHub data directory (for archive + logs)')
    p.add_argument('--force', action='store_true', help='Overwrite non-empty PostgreSQL tables')
    p.add_argument('--dry-run', action='store_true', help='Validate only; do not copy or archive SQLite')
    return p.parse_args()


def _target_has_data(session, table_names: list[str]) -> bool:
    from sqlalchemy import text

    for name in table_names:
        try:
            n = session.execute(text(f'SELECT COUNT(*) FROM {name}')).scalar() or 0
            if int(n) > 0:
                return True
        except Exception:
            continue
    return False


def _copy_table(src_engine, tgt_session, table) -> int:
    from sqlalchemy import inspect, text

    name = table.name
    if name not in inspect(src_engine).get_table_names():
        return 0

    with src_engine.connect() as src_conn:
        result = src_conn.execute(text(f'SELECT * FROM {name}'))
        mappings = result.mappings().all()

    if not mappings:
        return 0

    tgt_session.execute(table.delete())
    tgt_session.flush()
    tgt_session.execute(table.insert(), [dict(row) for row in mappings])
    tgt_session.commit()
    return len(mappings)


def _reset_all_sequences(tgt_session, metadata) -> list[str]:
    from utils.schema_migrations import reset_all_postgres_sequences

    return reset_all_postgres_sequences(tgt_session, metadata)


def main() -> int:
    args = _parse_args()
    sqlite_path = os.path.abspath(args.sqlite_path)
    if not os.path.isfile(sqlite_path):
        print(f'[migrate] ERROR: SQLite file not found: {sqlite_path}', file=sys.stderr)
        return 1

    data_dir = (args.data_dir or os.environ.get('ZIOCHUB_DATA_DIR') or os.path.dirname(sqlite_path)).strip()
    log_path = os.path.join(data_dir, 'migrate_sqlite_to_postgres.log')
    os.makedirs(data_dir, exist_ok=True)

    def log(msg: str) -> None:
        line = f'[{datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}] {msg}'
        print(line)
        try:
            with open(log_path, 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
        except OSError:
            pass

    os.environ.setdefault('FLASK_APP', 'app')
    os.environ['ZIOCHUB_SKIP_DB_INIT'] = '1'
    from utils.db_config import ensure_postgresql_env_loaded

    ensure_postgresql_env_loaded(data_dir)
    if 'ZIOCHUB_DATABASE_URL' not in os.environ and not os.environ.get('ZIOCHUB_PG_PASSWORD'):
        log('ERROR: PostgreSQL not configured (ZIOCHUB_DATABASE_URL / ZIOCHUB_PG_* missing)')
        log(f'Hint: run setup.sh --upgrade or create {os.path.join(data_dir, "ziochub.env")}')
        return 1

    from sqlalchemy import create_engine, inspect

    src_uri = 'sqlite:///' + sqlite_path.replace('\\', '/')
    src_engine = create_engine(src_uri)

    from app import app, db
    import models  # noqa: F401 — register all tables on metadata

    with app.app_context():
        if db.engine.dialect.name != 'postgresql':
            log(f'ERROR: Target database must be PostgreSQL (got {db.engine.dialect.name})')
            return 1

        log(f'Source: {sqlite_path}')
        log(f'Target: {db.engine.url.render_as_string(hide_password=True)}')

        db.create_all()
        table_names = [t.name for t in db.metadata.sorted_tables]
        if _target_has_data(db.session, table_names) and not args.force:
            log('ERROR: Target PostgreSQL already contains data. Re-run with --force after backup.')
            return 1

        if args.dry_run:
            log('Dry run OK — source readable, target PostgreSQL reachable.')
            return 0

        total_rows = 0
        for table in db.metadata.sorted_tables:
            try:
                n = _copy_table(src_engine, db.session, table)
                if n:
                    log(f'  {table.name}: {n} row(s)')
                    total_rows += n
            except Exception as exc:
                db.session.rollback()
                log(f'  {table.name}: FAILED — {exc}')
                return 1

        log(f'Migration complete — {total_rows} total row(s) copied.')

        try:
            reset_tables = _reset_all_sequences(db.session, db.metadata)
            log(f'Sequences reset for {len(reset_tables)} table(s).')
        except Exception as exc:
            db.session.rollback()
            log(f'WARNING: sequence reset failed — {exc}')
            log('Run: sudo -u ziochub python3 /opt/ziochub/scripts/fix_postgres_sequences.py')

    ts = datetime.now(timezone.utc).replace(tzinfo=None).strftime('%Y%m%d_%H%M%S')
    archive = f'{sqlite_path}.pre_postgresql_{ts}'
    shutil.move(sqlite_path, archive)
    log(f'SQLite archived: {archive}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
