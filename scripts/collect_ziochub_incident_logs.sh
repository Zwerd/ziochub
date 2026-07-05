#!/usr/bin/env bash
# ZIoCHub incident log collector — run on PROD (ioc-feed), redirect output and send to support.
# Usage: sudo bash collect_ziochub_incident_logs.sh 2>&1 | tee ziochub_incident_$(date +%Y%m%d_%H%M%S).txt

set -uo pipefail

INCIDENT_DATE="${INCIDENT_DATE:-2026-07-05}"
SINCE="${SINCE:-${INCIDENT_DATE} 07:45:00}"
UNTIL="${UNTIL:-${INCIDENT_DATE} 10:15:00}"
ZIOCHUB_DIR="${ZIOCHUB_DIR:-/opt/ziochub}"
DATA_DIR="${DATA_DIR:-${ZIOCHUB_DIR}/data}"

section() { echo; echo "===== $* ====="; echo; }

section "HOST / TIME"
hostname -f 2>/dev/null || hostname
date -Is 2>/dev/null || date
uname -a

section "SERVICE STATUS (current)"
systemctl is-active ziochub 2>/dev/null || true
systemctl is-active postgresql 2>/dev/null || true
systemctl list-timers --all 2>/dev/null | grep -iE 'ziochub|misp|taxii' || true

section "AUDIT CEF — MISP/TAXII/ADVERSARYGRAPH (${INCIDENT_DATE})"
if [[ -f "${DATA_DIR}/audit_cef.log" ]]; then
  grep -E 'misp_sync|taxii_sync|adversarygraph' "${DATA_DIR}/audit_cef.log" 2>/dev/null | grep "${INCIDENT_DATE}" || echo "(no matches)"
else
  echo "(missing ${DATA_DIR}/audit_cef.log)"
fi

section "AUDIT CEF — rotated (${INCIDENT_DATE})"
if compgen -G "${DATA_DIR}/audit_cef.log*" >/dev/null 2>&1; then
  zgrep -h -E 'misp_sync|taxii_sync|adversarygraph' "${DATA_DIR}"/audit_cef.log* 2>/dev/null | grep "${INCIDENT_DATE}" || echo "(no matches)"
else
  echo "(no audit_cef.log* files)"
fi

section "JOURNAL — ziochub-misp-sync.service (${SINCE} .. ${UNTIL})"
journalctl -u ziochub-misp-sync.service --since "${SINCE}" --until "${UNTIL}" --no-pager 2>/dev/null || echo "(journal unavailable)"

section "JOURNAL — ziochub-taxii-sync.service (${SINCE} .. ${UNTIL})"
journalctl -u ziochub-taxii-sync.service --since "${SINCE}" --until "${UNTIL}" --no-pager 2>/dev/null || echo "(unit missing or no entries)"

section "JOURNAL — ziochub (${SINCE} .. ${UNTIL}) — first 120 lines"
journalctl -u ziochub --since "${SINCE}" --until "${UNTIL}" --no-pager 2>/dev/null | head -120 || echo "(journal unavailable)"

section "JOURNAL — ziochub (${INCIDENT_DATE} 07:45 .. 08:05) — pre-incident"
journalctl -u ziochub --since "${INCIDENT_DATE} 07:45:00" --until "${INCIDENT_DATE} 08:05:00" --no-pager 2>/dev/null || echo "(journal unavailable)"

section "JOURNAL — ziochub (${INCIDENT_DATE} 08:00 .. 10:05) — grep non-timeout"
journalctl -u ziochub --since "${INCIDENT_DATE} 08:00:00" --until "${INCIDENT_DATE} 10:05:00" --no-pager 2>/dev/null \
  | grep -vE 'WORKER TIMEOUT|Error handling request \(no URI read\)|Traceback|gunicorn/|SystemExit|SIGKILL|Perhaps out of memory|Booting worker|Control socket listening|ssl\.py|unreader\.py|message\.py|parser\.py|sync\.py|handle_abort' \
  | head -200 || echo "(journal unavailable or all filtered)"

section "JOURNAL — postgresql (${SINCE} .. ${UNTIL}) — errors/locks/timeouts"
journalctl -u postgresql --since "${SINCE}" --until "${UNTIL}" --no-pager 2>/dev/null \
  | grep -iE 'duration|deadlock|lock|timeout|canceling|error|fatal' || echo "(no matches or journal unavailable)"

section "DMESG — OOM / killed process"
dmesg -T 2>/dev/null | grep -iE 'out of memory|oom|killed process' | tail -40 || echo "(dmesg unavailable)"

section "MEMORY / TOP PROCESSES (current snapshot)"
free -h 2>/dev/null || true
ps aux --sort=-%mem 2>/dev/null | head -15 || true

section "GUNICORN CONFIG (start.sh excerpt)"
if [[ -f "${ZIOCHUB_DIR}/start.sh" ]]; then
  grep -E 'WORKERS|TIMEOUT|PORT|gunicorn' "${ZIOCHUB_DIR}/start.sh" || true
else
  echo "(missing ${ZIOCHUB_DIR}/start.sh)"
fi

section "MISP SETTINGS — ziochub.env (redacted secrets)"
ENV_FILE="${DATA_DIR}/ziochub.env"
if [[ -f "${ENV_FILE}" ]]; then
  grep -E '^ZIOCHUB_PG_|^ZIOCHUB_DATABASE_URL|^MISP|^ZIOCHUB_' "${ENV_FILE}" 2>/dev/null \
    | sed -E 's/(PASSWORD|SECRET|API_KEY|KEY)=.*/\1=***REDACTED***/i' || true
else
  echo "(missing ${ENV_FILE})"
fi

section "MISP SETTINGS — system_settings (DB)"
if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}" 2>/dev/null || true
  set +a
fi
PGHOST="${ZIOCHUB_PG_HOST:-127.0.0.1}"
PGPORT="${ZIOCHUB_PG_PORT:-5432}"
PGUSER="${ZIOCHUB_PG_USER:-ziochub}"
PGDATABASE="${ZIOCHUB_PG_DATABASE:-ziochub}"
export PGPASSWORD="${ZIOCHUB_PG_PASSWORD:-}"
if command -v psql >/dev/null 2>&1 && [[ -n "${PGPASSWORD}" || -n "${ZIOCHUB_DATABASE_URL:-}" ]]; then
  if [[ -n "${ZIOCHUB_DATABASE_URL:-}" ]]; then
    psql "${ZIOCHUB_DATABASE_URL}" -c "SELECT key, value FROM system_settings WHERE key LIKE 'misp_%' ORDER BY key;" 2>&1 \
      | sed -E 's/(misp_api_key[^|]*\| )[^ ]+/\1***REDACTED***/i' || true
  else
    psql -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" \
      -c "SELECT key, value FROM system_settings WHERE key LIKE 'misp_%' ORDER BY key;" 2>&1 \
      | sed -E 's/(misp_api_key[^|]*\| )[^ ]+/\1***REDACTED***/i' || true
  fi
else
  echo "(psql unavailable or DB credentials missing — skip or run SQL manually)"
fi
unset PGPASSWORD 2>/dev/null || true

section "DATA DIR — lock / marker files"
ls -la "${DATA_DIR}/.misp_sync.lock" 2>/dev/null || echo "(no .misp_sync.lock)"
ls -la "${DATA_DIR}/.champs_leaderboard_invalidated" 2>/dev/null || true

section "DONE"
echo "Collector finished at $(date -Is 2>/dev/null || date)"
