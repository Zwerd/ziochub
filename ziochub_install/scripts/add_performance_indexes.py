#!/usr/bin/env python3
"""
Create performance indexes on existing database (IOC, IocHistory, ActivityEvent, YaraRule).
Safe to run multiple times (CREATE INDEX IF NOT EXISTS).
Run from project root: python scripts/add_performance_indexes.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from extensions import db


INDEXES = [
    ('iocs', 'ix_iocs_created_at', ['created_at']),
    ('iocs', 'ix_iocs_expiration_date', ['expiration_date']),
    ('iocs', 'ix_iocs_campaign_id', ['campaign_id']),
    ('iocs', 'ix_iocs_analyst', ['analyst']),
    ('ioc_history', 'ix_ioc_history_at', ['at']),
    ('ioc_history', 'ix_ioc_history_at_event_type', ['at', 'event_type']),
    ('activity_events', 'ix_activity_events_created_at', ['created_at']),
    ('activity_events', 'ix_activity_events_event_type', ['event_type']),
    ('yara_rules', 'ix_yara_rules_uploaded_at', ['uploaded_at']),
    ('yara_rules', 'ix_yara_rules_uploaded_at_status', ['uploaded_at', 'status']),
]


def main():
    with app.app_context():
        for table, name, columns in INDEXES:
            cols = ', '.join(columns)
            sql = f'CREATE INDEX IF NOT EXISTS {name} ON {table} ({cols})'
            try:
                db.session.execute(db.text(sql))
                db.session.commit()
                print(f'OK: {name}')
            except Exception as e:
                db.session.rollback()
                print(f'Skip/Error {name}: {e}')


if __name__ == '__main__':
    main()
