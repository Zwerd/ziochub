#!/usr/bin/env bash
# ============================================================================
#  ZIoCHub - Local backup (offline-safe, no network)
# ============================================================================
#  Creates a timestamped backup of:
#    - ziochub.db (SQLite database)
#    - data/ssl/     (SSL certificates)
#    - data/YARA/    (approved YARA rules)
#    - data/allowlist.txt
#
#  Backups older than RETENTION_DAYS are auto-removed.
#
#  Usage:
#    ./backup_ziochub.sh
#    ZIOCHUB_DATA_DIR=/path/to/data ./backup_ziochub.sh
#
#  Schedule: cron "0 2 * * *" or systemd timer (see ziochub-backup.timer)
# ============================================================================
set -euo pipefail

DATA_DIR="${ZIOCHUB_DATA_DIR:-/opt/ziochub/data}"
BACKUP_DIR="${DATA_DIR}/backups"
DB_FILE="${DATA_DIR}/ziochub.db"
RETENTION_DAYS=30

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DEST="${BACKUP_DIR}/${TIMESTAMP}"

if [[ ! -f "${DB_FILE}" ]]; then
    echo "[backup] No database at ${DB_FILE}; skipping."
    exit 0
fi

mkdir -p "${BACKUP_DEST}"

# Database
cp -a "${DB_FILE}" "${BACKUP_DEST}/ziochub.db"
echo "[backup] Database backed up"

# SSL certificates
if [[ -d "${DATA_DIR}/ssl" ]] && ls "${DATA_DIR}/ssl/"*.pem &>/dev/null 2>&1; then
    mkdir -p "${BACKUP_DEST}/ssl"
    cp -a "${DATA_DIR}/ssl/"*.pem "${BACKUP_DEST}/ssl/"
    echo "[backup] SSL certificates backed up"
fi

# YARA rules
if [[ -d "${DATA_DIR}/YARA" ]] && ls "${DATA_DIR}/YARA/"*.yar &>/dev/null 2>&1; then
    mkdir -p "${BACKUP_DEST}/YARA"
    cp -a "${DATA_DIR}/YARA/"*.yar "${BACKUP_DEST}/YARA/"
    YARA_COUNT=$(ls -1 "${BACKUP_DEST}/YARA/"*.yar 2>/dev/null | wc -l)
    echo "[backup] ${YARA_COUNT} YARA rules backed up"
fi

# Allowlist
if [[ -f "${DATA_DIR}/allowlist.txt" ]]; then
    cp -a "${DATA_DIR}/allowlist.txt" "${BACKUP_DEST}/"
    echo "[backup] Allowlist backed up"
fi

echo "[backup] Created ${BACKUP_DEST}"

# Remove backups older than RETENTION_DAYS
find "${BACKUP_DIR}" -maxdepth 1 -mindepth 1 -type d -mtime +${RETENTION_DAYS} -exec rm -rf {} \; 2>/dev/null || true
echo "[backup] Cleaned backups older than ${RETENTION_DAYS} days"
