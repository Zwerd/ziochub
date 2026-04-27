#!/usr/bin/env python3
"""
ZIoCHub - Expired IOC Cleanup Script
=====================================
Revokes IOC rows whose expiration_date has passed from the SQLite database,
logs each revocation to ioc_history. The IOC row remains so TAXII/STIX clients
can receive a revoked=true update for the same indicator id.

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
    Revoke IOC rows where expiration_date is non-NULL and in the past (soft-delete).
    Logs each revocation to ioc_history and updates iocs.revoked / modified_at.
    Returns the number of rows revoked.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        # Ensure revocation columns exist (older DBs may predate the migration).
        try:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(iocs)").fetchall()]
            if "revoked" not in cols:
                conn.execute("ALTER TABLE iocs ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT 0")
            if "revoked_at" not in cols:
                conn.execute("ALTER TABLE iocs ADD COLUMN revoked_at DATETIME")
            if "modified_at" not in cols:
                conn.execute("ALTER TABLE iocs ADD COLUMN modified_at DATETIME")
            conn.commit()
        except Exception as e:
            print(f"[cleaner] WARNING: could not ensure revocation columns: {e}")

        expired_rows = conn.execute(
            "SELECT id, type, value, analyst FROM iocs "
            "WHERE expiration_date IS NOT NULL AND expiration_date < ? "
            "AND (revoked IS NULL OR revoked = 0)",
            (now,),
        ).fetchall()

        if not expired_rows:
            return 0

        # Cisco ESA: remove dictionary words before IOC rows are deleted (uses system_settings from DB).
        try:
            esa_rows = conn.execute(
                "SELECT key, value FROM system_settings WHERE key LIKE 'esa_%'"
            ).fetchall()
            from utils.cisco_esa import esa_settings_from_sqlite_rows, process_expired_ioc_rows_for_esa

            esa_cfg = esa_settings_from_sqlite_rows([(r[0], r[1]) for r in esa_rows])
            pairs = [(row["type"], row["value"]) for row in expired_rows]
            process_expired_ioc_rows_for_esa(
                pairs,
                esa_cfg,
                log_fn=lambda m: print(f"[cleaner] {m}"),
            )
        except Exception as e:
            print(f"[cleaner] ESA cleanup skipped or failed: {e}")

        for row in expired_rows:
            payload = json.dumps({'source': 'cleaner', 'reason': 'ttl_expired'})
            conn.execute(
                "INSERT INTO ioc_history (ioc_type, ioc_value, event_type, username, at, payload) "
                "VALUES (?, ?, 'expired', ?, ?, ?)",
                (row['type'], row['value'], row['analyst'] or 'system', now, payload),
            )

        cursor = conn.execute(
            "UPDATE iocs SET revoked = 1, revoked_at = ?, modified_at = ? "
            "WHERE expiration_date IS NOT NULL AND expiration_date < ? AND (revoked IS NULL OR revoked = 0)",
            (now, now, now),
        )
        deleted = cursor.rowcount
        conn.commit()
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
