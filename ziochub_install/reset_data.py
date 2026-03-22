#!/usr/bin/env python3
"""
ZIoCHub - Data Reset Script
============================
Wipes operational data from the SQLite database so the system returns to
a clean state (useful for dev/test or before a fresh deployment).

Usage:
    python reset_data.py                 # interactive - asks before each category
    python reset_data.py --all           # wipe everything (IOCs, YARA, campaigns, history, champs, sessions)
    python reset_data.py --iocs          # wipe IOCs + IOC history only
    python reset_data.py --yara          # wipe YARA rules + files on disk
    python reset_data.py --campaigns     # wipe campaigns (unlinks IOCs first)
    python reset_data.py --history       # wipe IOC history + audit log
    python reset_data.py --champs        # wipe Champs data (goals, events, snapshots)
    python reset_data.py --sessions      # wipe user sessions
    python reset_data.py --exclusions    # wipe sanity exclusions
    python reset_data.py --settings      # reset MISP settings (disables MISP sync)
    python reset_data.py --playbook      # wipe custom Playbook items (keeps built-in)
    python reset_data.py --keep-users    # with --all: keep users & profiles intact
    python reset_data.py --yes           # skip confirmation prompts

Flags can be combined:  python reset_data.py --iocs --yara --history --yes

NOTE: Stop the ZIoCHub service before running this script to avoid
      database-lock conflicts:  sudo systemctl stop ziochub
"""

import argparse
import glob
import os
import shutil
import sqlite3
import sys
from datetime import datetime

try:
    import config as _config
except ImportError:
    _config = None

_base_dir = os.path.dirname(os.path.abspath(__file__))
_data_dir = (_config and _config.DATA_DIR) or os.path.join(_base_dir, 'data')
_db_path = (_config and getattr(_config, 'DB_PATH', None)) or os.path.join(_data_dir, 'ziochub.db')

DATA_YARA = os.path.join(_data_dir, 'YARA')
DATA_YARA_PENDING = os.path.join(_data_dir, 'YARA_pending')
AUDIT_LOG = os.path.join(_data_dir, 'audit.log')
PLAYBOOK_CUSTOM_FILE = os.path.join(_data_dir, 'playbook_custom.json')

COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'cyan': '\033[96m',
    'bold': '\033[1m',
    'reset': '\033[0m',
}


def c(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def confirm(msg, auto_yes=False):
    if auto_yes:
        return True
    answer = input(f"  {msg} [y/N]: ").strip().lower()
    return answer in ('y', 'yes')


def table_count(conn, table):
    try:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def delete_table(conn, table):
    count = table_count(conn, table)
    conn.execute(f"DELETE FROM {table}")
    return count


def wipe_iocs(conn, auto_yes):
    ioc_count = table_count(conn, 'iocs')
    hist_count = table_count(conn, 'ioc_history')
    print(f"\n  {c('IOCs:', 'bold')}          {ioc_count} rows")
    print(f"  {c('IOC History:', 'bold')}  {hist_count} rows")
    if ioc_count + hist_count == 0:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete all {ioc_count} IOCs and {hist_count} history records?", auto_yes):
        print("  Skipped.")
        return
    deleted_iocs = delete_table(conn, 'iocs')
    deleted_hist = delete_table(conn, 'ioc_history')
    conn.commit()
    print(f"  {c(f'Deleted {deleted_iocs} IOCs, {deleted_hist} history records.', 'green')}")


def wipe_yara(conn, auto_yes):
    yara_count = table_count(conn, 'yara_rules')
    yara_files = glob.glob(os.path.join(DATA_YARA, '*.yar'))
    pending_files = glob.glob(os.path.join(DATA_YARA_PENDING, '*.yar'))
    print(f"\n  {c('YARA rules (DB):', 'bold')}       {yara_count} rows")
    print(f"  {c('YARA files (disk):', 'bold')}      {len(yara_files)} in YARA/")
    print(f"  {c('YARA pending (disk):', 'bold')}    {len(pending_files)} in YARA_pending/")
    total = yara_count + len(yara_files) + len(pending_files)
    if total == 0:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete all YARA rules (DB + files)?", auto_yes):
        print("  Skipped.")
        return
    deleted = delete_table(conn, 'yara_rules')
    conn.commit()
    for f in yara_files + pending_files:
        os.remove(f)
    print(f"  {c(f'Deleted {deleted} DB rows, {len(yara_files) + len(pending_files)} files.', 'green')}")


def wipe_campaigns(conn, auto_yes):
    camp_count = table_count(conn, 'campaigns')
    print(f"\n  {c('Campaigns:', 'bold')}  {camp_count} rows")
    if camp_count == 0:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete all {camp_count} campaigns (IOCs will be unlinked)?", auto_yes):
        print("  Skipped.")
        return
    conn.execute("UPDATE iocs SET campaign_id = NULL WHERE campaign_id IS NOT NULL")
    conn.execute("UPDATE yara_rules SET campaign_id = NULL WHERE campaign_id IS NOT NULL")
    deleted = delete_table(conn, 'campaigns')
    conn.commit()
    print(f"  {c(f'Deleted {deleted} campaigns, unlinked IOCs and YARA rules.', 'green')}")


def wipe_history(conn, auto_yes):
    hist_count = table_count(conn, 'ioc_history')
    audit_exists = os.path.isfile(AUDIT_LOG)
    audit_size = os.path.getsize(AUDIT_LOG) if audit_exists else 0
    audit_size_kb = f"{audit_size / 1024:.1f} KB" if audit_exists else "N/A"
    print(f"\n  {c('IOC History:', 'bold')}  {hist_count} rows")
    print(f"  {c('Audit log:', 'bold')}    {audit_size_kb}")
    if hist_count == 0 and not audit_exists:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete IOC history ({hist_count} rows) and truncate audit log?", auto_yes):
        print("  Skipped.")
        return
    deleted = delete_table(conn, 'ioc_history')
    conn.commit()
    if audit_exists:
        open(AUDIT_LOG, 'w').close()
    # Also clean rotated audit log files
    for rotated in glob.glob(AUDIT_LOG + '.*'):
        os.remove(rotated)
    print(f"  {c(f'Deleted {deleted} history records, audit log truncated.', 'green')}")


def wipe_exclusions(conn, auto_yes):
    excl_count = table_count(conn, 'sanity_exclusions')
    print(f"\n  {c('Sanity Exclusions:', 'bold')}  {excl_count} rows")
    if excl_count == 0:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete all {excl_count} sanity exclusions?", auto_yes):
        print("  Skipped.")
        return
    deleted = delete_table(conn, 'sanity_exclusions')
    conn.commit()
    print(f"  {c(f'Deleted {deleted} exclusions.', 'green')}")


def wipe_champs(conn, auto_yes):
    goals = table_count(conn, 'team_goals')
    events = table_count(conn, 'activity_events')
    snapshots = table_count(conn, 'champ_rank_snapshots')
    print(f"\n  {c('Team Goals:', 'bold')}       {goals} rows")
    print(f"  {c('Activity Events:', 'bold')}  {events} rows")
    print(f"  {c('Rank Snapshots:', 'bold')}   {snapshots} rows")
    total = goals + events + snapshots
    if total == 0:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete all Champs data ({total} total rows)?", auto_yes):
        print("  Skipped.")
        return
    d1 = delete_table(conn, 'team_goals')
    d2 = delete_table(conn, 'activity_events')
    d3 = delete_table(conn, 'champ_rank_snapshots')
    conn.commit()
    print(f"  {c(f'Deleted {d1} goals, {d2} events, {d3} snapshots.', 'green')}")


def wipe_sessions(conn, auto_yes):
    sess_count = table_count(conn, 'user_sessions')
    print(f"\n  {c('User Sessions:', 'bold')}  {sess_count} rows")
    if sess_count == 0:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete all {sess_count} session records?", auto_yes):
        print("  Skipped.")
        return
    deleted = delete_table(conn, 'user_sessions')
    conn.commit()
    print(f"  {c(f'Deleted {deleted} sessions.', 'green')}")


def wipe_settings(conn, auto_yes):
    try:
        total = table_count(conn, 'system_settings')
    except Exception:
        print(f"\n  {c('System Settings:', 'bold')}  table not found, skipping.")
        return
    misp_rows = conn.execute(
        "SELECT key FROM system_settings WHERE key LIKE 'misp_%'"
    ).fetchall()
    misp_count = len(misp_rows)
    print(f"\n  {c('System Settings:', 'bold')}    {total} total rows")
    print(f"  {c('MISP settings:', 'bold')}      {misp_count} rows")
    if misp_count == 0:
        print(f"  {c('No MISP settings to clean.', 'green')}")
        return
    if not confirm(f"Reset all {misp_count} MISP settings (disables MISP sync)?", auto_yes):
        print("  Skipped.")
        return
    conn.execute("DELETE FROM system_settings WHERE key LIKE 'misp_%'")
    conn.commit()
    print(f"  {c(f'Deleted {misp_count} MISP settings. MISP sync is now disabled.', 'green')}")


def wipe_playbook(auto_yes):
    if os.path.isfile(PLAYBOOK_CUSTOM_FILE):
        try:
            import json
            with open(PLAYBOOK_CUSTOM_FILE, 'r', encoding='utf-8') as f:
                items = json.load(f)
            count = len(items) if isinstance(items, list) else 0
        except Exception:
            count = '?'
    else:
        count = 0
    print(f"\n  {c('Playbook custom items:', 'bold')}  {count} items")
    print(f"  {c('(built-in items are never deleted)', 'cyan')}")
    if count == 0:
        print(f"  {c('Nothing to clean.', 'green')}")
        return
    if not confirm(f"Delete all {count} custom Playbook items (sites, groups, workflows)?", auto_yes):
        print("  Skipped.")
        return
    os.remove(PLAYBOOK_CUSTOM_FILE)
    print(f"  {c(f'Deleted {count} custom Playbook items. Built-in items remain.', 'green')}")


def wipe_users(conn, auto_yes):
    admin_row = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    admin_id = admin_row[0] if admin_row else None
    user_count = table_count(conn, 'users')
    profile_count = table_count(conn, 'user_profiles')
    deletable = user_count - (1 if admin_id else 0)
    print(f"\n  {c('Users:', 'bold')}          {user_count} rows ({c('admin preserved', 'cyan')})")
    print(f"  {c('User Profiles:', 'bold')}  {profile_count} rows")
    if deletable <= 0:
        print(f"  {c('Nothing to clean (only admin exists).', 'green')}")
        return
    if not confirm(f"Delete {deletable} users and their profiles (admin will be kept)?", auto_yes):
        print("  Skipped.")
        return
    if admin_id:
        conn.execute("DELETE FROM user_profiles WHERE user_id != ?", (admin_id,))
        conn.execute("DELETE FROM user_sessions WHERE user_id != ?", (admin_id,))
        conn.execute("UPDATE iocs SET user_id = NULL WHERE user_id IS NOT NULL AND user_id != ?", (admin_id,))
        conn.execute("DELETE FROM users WHERE id != ?", (admin_id,))
    else:
        delete_table(conn, 'user_profiles')
        delete_table(conn, 'user_sessions')
        conn.execute("UPDATE iocs SET user_id = NULL WHERE user_id IS NOT NULL")
        delete_table(conn, 'users')
    conn.commit()
    print(f"  {c(f'Deleted {deletable} users (admin kept).', 'green')}")


def vacuum(conn):
    print(f"\n  Running VACUUM...")
    conn.execute("VACUUM")
    print(f"  {c('Done. Database compacted.', 'green')}")


def main():
    parser = argparse.ArgumentParser(
        description='ZIoCHub - Data Reset Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Stop the ZIoCHub service before running:\n  sudo systemctl stop ziochub',
    )
    parser.add_argument('--all', action='store_true', help='Wipe all data')
    parser.add_argument('--iocs', action='store_true', help='Wipe IOCs + IOC history')
    parser.add_argument('--yara', action='store_true', help='Wipe YARA rules (DB + disk files)')
    parser.add_argument('--campaigns', action='store_true', help='Wipe campaigns')
    parser.add_argument('--history', action='store_true', help='Wipe IOC history + audit log')
    parser.add_argument('--champs', action='store_true', help='Wipe Champs data (goals, events, snapshots)')
    parser.add_argument('--sessions', action='store_true', help='Wipe user sessions')
    parser.add_argument('--exclusions', action='store_true', help='Wipe sanity exclusions')
    parser.add_argument('--settings', action='store_true', help='Reset MISP settings (disables MISP sync)')
    parser.add_argument('--playbook', action='store_true', help='Wipe custom Playbook items (keeps built-in)')
    parser.add_argument('--keep-users', action='store_true', help='With --all: keep users & profiles')
    parser.add_argument('--yes', '-y', action='store_true', help='Skip confirmation prompts')
    args = parser.parse_args()

    interactive = not any([args.all, args.iocs, args.yara, args.campaigns,
                           args.history, args.champs, args.sessions, args.exclusions,
                           args.settings, args.playbook])

    print(f"\n{c('=== ZIoCHub Data Reset ===', 'bold')}")
    print(f"  Database: {_db_path}")
    print(f"  Time:     {datetime.now().isoformat()}")

    if not os.path.exists(_db_path):
        print(f"\n  {c('ERROR:', 'red')} Database not found at {_db_path}")
        sys.exit(1)

    if args.all and not args.yes:
        print(f"\n  {c('WARNING:', 'red')} --all will delete ALL operational data!")
        if not confirm(f"Are you sure you want to continue?"):
            print("  Aborted.")
            sys.exit(0)

    conn = sqlite3.connect(_db_path)
    try:
        if args.all or args.iocs or interactive:
            wipe_iocs(conn, args.yes and not interactive)

        if args.all or args.yara or interactive:
            wipe_yara(conn, args.yes and not interactive)

        if args.all or args.campaigns or interactive:
            wipe_campaigns(conn, args.yes and not interactive)

        if args.all or args.exclusions or interactive:
            wipe_exclusions(conn, args.yes and not interactive)

        if args.all or args.history or interactive:
            wipe_history(conn, args.yes and not interactive)

        if args.all or args.champs or interactive:
            wipe_champs(conn, args.yes and not interactive)

        if args.all or args.sessions or interactive:
            wipe_sessions(conn, args.yes and not interactive)

        if args.all or args.settings or interactive:
            wipe_settings(conn, args.yes and not interactive)

        if args.all or args.playbook or interactive:
            wipe_playbook(args.yes and not interactive)

        if args.all and not args.keep_users:
            wipe_users(conn, args.yes)
        elif interactive:
            wipe_users(conn, False)

        vacuum(conn)
    finally:
        conn.close()

    print(f"\n{c('Reset complete.', 'bold')}\n")


if __name__ == '__main__':
    main()
