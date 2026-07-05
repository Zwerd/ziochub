#!/usr/bin/env python3
"""Smoke-test Champs leaderboard SQL against the configured database."""
from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)


def main() -> int:
    from utils.db_config import ensure_postgresql_env_loaded

    data_dir = os.environ.get('ZIOCHUB_DATA_DIR') or os.path.join(BASE_DIR, 'data')
    if not ensure_postgresql_env_loaded(data_dir):
        print(f'ERROR: missing {os.path.join(data_dir, "ziochub.env")}', file=sys.stderr)
        return 1

    from app import app, db
    from models import IOC, YaraRule, User, ActivityEvent
    from utils.champs import compute_analyst_scores

    with app.app_context():
        if db.engine.dialect.name != 'postgresql':
            print(f'ERROR: expected postgresql, got {db.engine.dialect.name}', file=sys.stderr)
            return 1
        try:
            rows = compute_analyst_scores(db, IOC, YaraRule, User, ActivityEvent, scoring_method='1')
        except Exception as exc:
            print(f'FAIL: compute_analyst_scores raised: {type(exc).__name__}: {exc}', file=sys.stderr)
            return 1
        print(f'OK: {len(rows)} analyst row(s)')
        for r in rows[:10]:
            print(f"  #{r.get('rank')} {r.get('analyst')} score={r.get('score')} iocs={r.get('total_iocs')}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
