#!/usr/bin/env python3
"""ZIoCHub – TAXII 2.1 inbound pull job (systemd timer)."""
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def main():
    ts = datetime.now().isoformat()
    os.environ.setdefault('FLASK_APP', 'app')
    from app import app
    from utils.taxii_sync_runner import run_taxii_sync_if_due_with_lock

    print(f'[taxii-sync] Job tick at {ts}')
    with app.app_context():
        result = run_taxii_sync_if_due_with_lock(app)
    if result.get('skipped'):
        print(f"[taxii-sync] Skipped ({result.get('skip_reason', 'unknown')})")
    print(f'[taxii-sync] Finished at {datetime.now().isoformat()}')


if __name__ == '__main__':
    main()
