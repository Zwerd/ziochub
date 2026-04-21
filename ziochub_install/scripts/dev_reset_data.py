#!/usr/bin/env python3
"""
ZIoCHub — Dev Data Reset
========================
Wipes all persistent data for a clean dev environment.
Run when the app is STOPPED to avoid DB lock.

Deletes:
  - data/ziochub.db
  - data/audit.log*
  - data/Main/*.txt (IOCs)
  - data/YARA/*.yar
  - static/avatars/* (user avatars, keeps default.svg)

Respects ZIOCHUB_DATA_DIR.
"""
import os
import sys
import glob

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.environ.get("ZIOCHUB_DATA_DIR", "").strip() or os.path.join(base_dir, "data")
    static_dir = os.path.join(base_dir, "static")
    avatars_dir = os.path.join(static_dir, "avatars")

    if not os.path.isdir(data_dir):
        print(f"Data dir does not exist: {data_dir}")
        return 0

    removed = []

    # Database
    db_path = os.path.join(data_dir, "ziochub.db")
    if os.path.isfile(db_path):
        os.remove(db_path)
        removed.append(db_path)

    # Audit log + rotated
    for p in glob.glob(os.path.join(data_dir, "audit.log*")):
        os.remove(p)
        removed.append(p)

    # Main IOC files (support Main or main)
    main_dir = None
    for name in (os.listdir(data_dir) if os.path.isdir(data_dir) else []):
        if name.lower() == "main" and os.path.isdir(os.path.join(data_dir, name)):
            main_dir = os.path.join(data_dir, name)
            break
    if main_dir is None:
        main_dir = os.path.join(data_dir, "Main")
    if os.path.isdir(main_dir):
        for f in ("ip.txt", "domain.txt", "hash.txt", "email.txt", "url.txt", "yara.txt"):
            p = os.path.join(main_dir, f)
            if os.path.isfile(p):
                os.remove(p)
                removed.append(p)

    # YARA rules
    yara_dir = os.path.join(data_dir, "YARA")
    if os.path.isdir(yara_dir):
        for p in glob.glob(os.path.join(yara_dir, "*.yar")):
            os.remove(p)
            removed.append(p)

    # User avatars (keep default.svg)
    if os.path.isdir(avatars_dir):
        for name in os.listdir(avatars_dir):
            if name != "default.svg" and not name.startswith("."):
                p = os.path.join(avatars_dir, name)
                if os.path.isfile(p):
                    os.remove(p)
                    removed.append(p)

    if removed:
        print("Removed:")
        for p in removed:
            print("  ", p)
    else:
        print("Nothing to remove (data already clean).")

    print("Done. Restart the app for a fresh start.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
