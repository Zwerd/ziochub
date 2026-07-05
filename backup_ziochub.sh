#!/usr/bin/env bash
# ============================================================================
#  ZIoCHub - Local backup (offline-safe, no network)
# ============================================================================
#  Creates a timestamped backup of:
#    - PostgreSQL database (pg_dump custom format + plain SQL)
#    - Legacy ziochub.db if still present (pre-migration archive)
#    - data/ssl/     (SSL certificates)
#    - data/YARA/    (approved YARA rules)
#    - data/allowlist.txt
#    - data/audit_cef.log (CEF audit trail)
#
#  Backups older than RETENTION_DAYS are auto-removed.
#
#  Usage:
#    ./backup_ziochub.sh
#    ZIOCHUB_DATA_DIR=/path/to/data ./backup_ziochub.sh
#
#  Schedule: systemd timer (ziochub-backup.timer)
# ============================================================================
set -euo pipefail

DATA_DIR="${ZIOCHUB_DATA_DIR:-/opt/ziochub/data}"
BACKUP_DIR="${DATA_DIR}/backups"
ENV_FILE="${DATA_DIR}/ziochub.env"
RETENTION_DAYS=30

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DEST="${BACKUP_DIR}/${TIMESTAMP}"

if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
fi

mkdir -p "${BACKUP_DEST}"

PG_HOST="${ZIOCHUB_PG_HOST:-127.0.0.1}"
PG_PORT="${ZIOCHUB_PG_PORT:-5432}"
PG_DB="${ZIOCHUB_PG_DB:-ziochub}"
PG_USER="${ZIOCHUB_PG_USER:-ziochub}"
PG_PASS="${ZIOCHUB_PG_PASSWORD:-}"

if command -v pg_dump &>/dev/null && [[ -n "${PG_PASS}" ]]; then
    export PGPASSWORD="${PG_PASS}"
    if pg_dump -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" \
        -Fc -f "${BACKUP_DEST}/ziochub.pgdump" 2>/dev/null; then
        echo "[backup] PostgreSQL custom dump: ziochub.pgdump"
    else
        echo "[backup] WARN: pg_dump custom format failed"
    fi
    if pg_dump -h "${PG_HOST}" -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" \
        -f "${BACKUP_DEST}/ziochub.sql" 2>/dev/null; then
        echo "[backup] PostgreSQL plain SQL: ziochub.sql"
    else
        echo "[backup] WARN: pg_dump plain SQL failed"
    fi
    unset PGPASSWORD
elif [[ -n "${ZIOCHUB_DATABASE_URL:-}" ]] && command -v pg_dump &>/dev/null; then
    if pg_dump "${ZIOCHUB_DATABASE_URL}" -Fc -f "${BACKUP_DEST}/ziochub.pgdump" 2>/dev/null; then
        echo "[backup] PostgreSQL dump via DATABASE_URL"
    fi
else
    echo "[backup] WARN: PostgreSQL backup skipped (pg_dump or credentials missing)"
fi

LEGACY_DB="${DATA_DIR}/ziochub.db"
if [[ -f "${LEGACY_DB}" ]]; then
    cp -a "${LEGACY_DB}" "${BACKUP_DEST}/ziochub.db"
    echo "[backup] Legacy SQLite file backed up"
fi

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

# CEF audit log
if [[ -f "${DATA_DIR}/audit_cef.log" ]]; then
    cp -a "${DATA_DIR}/audit_cef.log" "${BACKUP_DEST}/"
    echo "[backup] CEF audit log backed up"
fi

{
    echo "ZIoCHub backup manifest"
    echo "Date: $(date -Iseconds 2>/dev/null || date)"
    echo "Data dir: ${DATA_DIR}"
    echo "PostgreSQL: ${PG_USER}@${PG_HOST}:${PG_PORT}/${PG_DB}"
} > "${BACKUP_DEST}/MANIFEST.txt"

echo "[backup] Created ${BACKUP_DEST}"

find "${BACKUP_DIR}" -maxdepth 1 -mindepth 1 -type d -mtime +${RETENTION_DAYS} -exec rm -rf {} \; 2>/dev/null || true
echo "[backup] Cleaned backups older than ${RETENTION_DAYS} days"
