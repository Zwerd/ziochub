#!/usr/bin/env python3
"""
ZIoCHub - AdversaryGraph Automatic Sync Job
============================================
Pulls IOCs from AdversaryGraph IOC Library and YARA rules from Detection Studio.

Designed to be triggered by systemd timer (optional). The same logic runs in-app
via ``utils.adversarygraph_sync_scheduler`` when the web service is up.
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
    from utils.adversarygraph_sync_runner import run_adversarygraph_sync_if_due_with_lock

    print(f"[adversarygraph-sync] Job tick at {ts}")
    with app.app_context():
        result = run_adversarygraph_sync_if_due_with_lock(app)
    if result.get('skipped'):
        print(f"[adversarygraph-sync] Skipped ({result.get('skip_reason', 'unknown')})")
    elif result.get('success'):
        print(
            f"[adversarygraph-sync] OK added={result.get('added', 0)} "
            f"yara_added={result.get('yara_added', 0)}"
        )
    else:
        print(f"[adversarygraph-sync] FAIL {result.get('error') or 'unknown'}")
    print(f"[adversarygraph-sync] Finished at {datetime.now().isoformat()}")


if __name__ == '__main__':
    main()
