#!/usr/bin/env python3
"""
ThreatGate – Expired IOC Cleanup Script
========================================
Deletes IOC rows whose expiration_date has passed from the SQLite database,
then runs VACUUM to reclaim disk space.

Designed to be triggered by systemd timer (threatgate-cleaner.timer).
All output goes to stdout/stderr so systemd captures it in the journal.
"""

import os
import sqlite3
from datetime import datetime


def get_db_path():
    """Resolve the path to threatgate.db relative to this script's location."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "data", "threatgate.db")


def clean_expired_iocs(db_path):
    """
    Delete IOC rows where expiration_date is non-NULL and in the past.
    Returns the number of rows removed.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute(
            "DELETE FROM iocs WHERE expiration_date IS NOT NULL AND expiration_date < ?",
            (now,),
        )
        deleted = cursor.rowcount
        conn.commit()

        # Reclaim disk space
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
        print(f"[cleaner] Removed {deleted} expired IOC(s).")
    else:
        print("[cleaner] No expired IOCs found. Nothing to do.")

    print(f"[cleaner] Finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
