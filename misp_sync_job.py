#!/usr/bin/env python3
"""
ZIoCHub - MISP Automatic Sync Job
==================================
Pulls new IOC attributes from a configured MISP instance and imports them
into ZIoCHub.

Designed to be triggered by systemd timer (ziochub-misp-sync.timer).
The timer fires frequently (every 5 min); this script checks the admin-
configured pull interval and exits early if it's not time yet.

The same logic runs in-app via ``utils.misp_sync_scheduler`` when the web
service is up (no systemd required).
"""

import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def main():
    ts = datetime.now().isoformat()
    os.environ.setdefault('FLASK_APP', 'app')
    from app import app
    from utils.misp_sync_runner import run_misp_sync_if_due_with_lock

    print(f"[misp-sync] Job tick at {ts}")
    with app.app_context():
        result = run_misp_sync_if_due_with_lock(app)
    if result.get('skipped'):
        print(f"[misp-sync] Skipped ({result.get('skip_reason', 'unknown')})")
    print(f"[misp-sync] Finished at {datetime.now().isoformat()}")


if __name__ == '__main__':
    main()
