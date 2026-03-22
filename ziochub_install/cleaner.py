#!/usr/bin/env python3
"""
ZIoCHub - Expired IOC Cleanup Script
=====================================
Deletes IOC rows whose expiration_date has passed from the SQLite database,
logs each deletion to ioc_history, then runs VACUUM to reclaim disk space.

Designed to be triggered by systemd timer (ziochub-cleaner.timer).
All output goes to stdout/stderr so systemd captures it in the journal.
"""

import json
import os
import sqlite3
from datetime import datetime


def get_db_path():
    """Resolve the path to ziochub.db. Uses ZIOCHUB_DATA_DIR if set, else relative to script."""
    data_dir = os.environ.get("ZIOCHUB_DATA_DIR", "").strip()
    if data_dir:
        return os.path.join(data_dir, "ziochub.db")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "data", "ziochub.db")


def clean_expired_iocs(db_path):
    """
    Delete IOC rows where expiration_date is non-NULL and in the past.
    Logs each deletion to ioc_history before removing.
    Returns the number of rows removed.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        expired_rows = conn.execute(
            "SELECT type, value, analyst FROM iocs "
            "WHERE expiration_date IS NOT NULL AND expiration_date < ?",
            (now,),
        ).fetchall()

        if not expired_rows:
            return 0

        for row in expired_rows:
            payload = json.dumps({'source': 'cleaner', 'reason': 'ttl_expired'})
            conn.execute(
                "INSERT INTO ioc_history (ioc_type, ioc_value, event_type, username, at, payload) "
                "VALUES (?, ?, 'expired', ?, ?, ?)",
                (row['type'], row['value'], row['analyst'] or 'system', now, payload),
            )

        cursor = conn.execute(
            "DELETE FROM iocs WHERE expiration_date IS NOT NULL AND expiration_date < ?",
            (now,),
        )
        deleted = cursor.rowcount
        conn.commit()

        conn.execute("VACUUM")
        return deleted
    finally:
        conn.close()


def main():
    db_path = get_db_path()

    print(f"[cleaner] Starting cleanup at {datetime.now().isoformat()}")
    print(f"[cleaner] Database: {db_path}")

    if not os.path.exists(db_path):
        print(f"[cleaner] ERROR: Database not found at {db_path}")
        return

    deleted = clean_expired_iocs(db_path)

    if deleted:
        print(f"[cleaner] Removed {deleted} expired IOC(s) and logged to history.")
    else:
        print("[cleaner] No expired IOCs found. Nothing to do.")

    print(f"[cleaner] Finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
