#!/usr/bin/env python3
"""
ZIoCHub - MISP Automatic Sync Job
==================================
Pulls new IOC attributes from a configured MISP instance and imports them
into ZIoCHub.

Designed to be triggered by systemd timer (ziochub-misp-sync.timer).
The timer fires frequently (every 5 min); this script checks the admin-
configured pull interval and exits early if it's not time yet.
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


def main():
    ts = datetime.now().isoformat()
    os.environ.setdefault('FLASK_APP', 'app')
    from app import app
    from models import SystemSetting
    from extensions import db

    with app.app_context():
        def _get(key, default=''):
            row = SystemSetting.query.filter_by(key=key).first()
            return (row.value or default) if row else default

        def _set(key, value):
            row = SystemSetting.query.filter_by(key=key).first()
            if row:
                row.value = value
            else:
                db.session.add(SystemSetting(key=key, value=value))
            db.session.commit()

        enabled = _get('misp_enabled', 'false')
        if enabled.lower() != 'true':
            return

        url = _get('misp_url', '')
        api_key = _get('misp_api_key', '')
        if not url or not api_key:
            return

        # Check if enough time has passed since last sync
        try:
            pull_interval_min = int(_get('misp_pull_interval', '60'))
        except (ValueError, TypeError):
            pull_interval_min = 60
        pull_interval_min = max(5, pull_interval_min)

        last_sync_str = _get('misp_last_sync', '')
        if last_sync_str:
            try:
                last_sync_dt = datetime.fromisoformat(last_sync_str)
                elapsed = datetime.now(timezone.utc).replace(tzinfo=None) - last_sync_dt
                if elapsed < timedelta(minutes=pull_interval_min):
                    return
            except (ValueError, TypeError):
                pass

        print(f"[misp-sync] Starting at {ts}")

        settings = {
            'misp_url': url,
            'misp_api_key': api_key,
            'misp_verify_ssl': _get('misp_verify_ssl', 'false'),
            'misp_last_days': _get('misp_last_days', '30'),
            'misp_filter_tags': _get('misp_filter_tags', ''),
            'misp_filter_types': _get('misp_filter_types', ''),
            'misp_published_only': _get('misp_published_only', 'true'),
            'misp_default_ttl': _get('misp_default_ttl', 'permanent'),
            'misp_sync_user': _get('misp_sync_user', 'misp_sync'),
        }

        from utils.misp_sync import run_sync
        result = run_sync(settings)

        now_str = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        _set('misp_last_sync', now_str)
        _set('misp_last_sync_result', json.dumps(result)[:1000])

        if result.get('success'):
            print(f"[misp-sync] Sync complete: fetched={result.get('fetched', 0)}, "
                  f"added={result.get('added', 0)}, skipped={result.get('skipped', 0)}, "
                  f"invalid={result.get('invalid', 0)}, errors={result.get('errors', 0)}")
        else:
            print(f"[misp-sync] Sync FAILED: {result.get('error', 'unknown')}")

    print(f"[misp-sync] Finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
