#!/usr/bin/env bash
# ============================================================================
#  ThreatGate — Full Uninstaller (Linux)
# ============================================================================
#  Removes ThreatGate completely: systemd services, processes, application
#  code, Python venv, database, IOC files, YARA rules, SSL certificates,
#  backups, and the threatgate system user/group.
#
#  Usage:
#    sudo ./uninstall.sh              # Interactive (asks confirmation)
#    sudo ./uninstall.sh --yes        # No confirmation, remove everything
#    sudo ./uninstall.sh --backup     # Backup data first, then remove all
#    sudo ./uninstall.sh --backup -y  # Backup + no confirmation
#    sudo ./uninstall.sh --help       # Full help with details
#
#  Post-removal reinstall:
#    sudo ./setup.sh                  # Online
#    sudo ./setup.sh --offline        # Offline (from installer ZIP)
# ============================================================================
set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Help ─────────────────────────────────────────────────────────────────────
show_help() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ThreatGate — Full Uninstaller${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Usage:  sudo ./uninstall.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --yes, -y       Skip confirmation prompt and remove everything."
    echo "  --backup, -b    Backup data directory before removal."
    echo "                  Backup is saved to /opt/threatgate_backup_<timestamp>/"
    echo "  --help, -h      Show this help message and exit."
    echo ""
    echo -e "${RED}══ What Gets Removed ══${NC}"
    echo ""
    echo "  Systemd services & timers (8 units):"
    echo "    - threatgate.service            (main app)"
    echo "    - threatgate-redirect.service   (HTTP→HTTPS redirect)"
    echo "    - threatgate-cleaner.service    + timer (expired IOC cleanup)"
    echo "    - threatgate-backup.service     + timer (daily DB backup)"
    echo "    - threatgate-misp-sync.service  + timer (MISP pull)"
    echo "    - Any systemd override directories (*.service.d/)"
    echo ""
    echo "  Application directory (/opt/threatgate):"
    echo "    - Python source code (app.py, utils/, routes/, templates/, static/)"
    echo "    - Virtual environment (venv/)"
    echo "    - SQLite database (data/threatgate.db)"
    echo "    - IOC files (data/Main/)"
    echo "    - YARA rules (data/YARA/, data/YARA_pending/)"
    echo "    - SSL certificates (data/ssl/)"
    echo "    - Backups (data/backups/)"
    echo "    - CEF audit logs (data/audit_cef.log)"
    echo "    - Config files (allowlist.txt, org_domains.txt, GeoIP DB)"
    echo ""
    echo "  System:"
    echo "    - All running ThreatGate processes (gunicorn, redirect)"
    echo "    - System user 'threatgate' and group 'threatgate'"
    echo ""
    echo -e "${GREEN}══ What Is NOT Removed ══${NC}"
    echo ""
    echo "  - System journal logs (cleaned by journal rotation)"
    echo "  - Python3 / system packages (apt packages)"
    echo "  - Backups created with --backup flag (saved outside /opt/threatgate)"
    echo ""
    echo -e "${YELLOW}══ Examples ══${NC}"
    echo ""
    echo "  Safe removal (backup first):"
    echo "    sudo ./uninstall.sh --backup"
    echo ""
    echo "  Quick removal (no prompts, no backup):"
    echo "    sudo ./uninstall.sh --yes"
    echo ""
    echo "  Backup + no prompts:"
    echo "    sudo ./uninstall.sh --backup --yes"
    echo ""
    echo "  Reinstall after removal:"
    echo "    sudo ./setup.sh                  # Online"
    echo "    sudo ./setup.sh --offline        # Offline (from installer ZIP)"
    echo ""
    exit 0
}

# ── Parse arguments ─────────────────────────────────────────────────────────
SKIP_CONFIRM=false
DO_BACKUP=false
for arg in "$@"; do
    case "$arg" in
        --help|-h)   show_help ;;
        --yes|-y)    SKIP_CONFIRM=true ;;
        --backup|-b) DO_BACKUP=true ;;
    esac
done

[[ $EUID -ne 0 ]] && fail "This script must be run as root (sudo ./uninstall.sh)"

# ── Constants ───────────────────────────────────────────────────────────────
APP_USER="threatgate"
APP_GROUP="threatgate"
APP_DIR="/opt/threatgate"
DATA_DIR="${APP_DIR}/data"
VENV_DIR="${APP_DIR}/venv"
BACKUP_DIR="/opt/threatgate_backup_$(date +%Y%m%d_%H%M%S)"

ALL_UNITS=(
    "threatgate.service"
    "threatgate-redirect.service"
    "threatgate-cleaner.service"
    "threatgate-cleaner.timer"
    "threatgate-backup.service"
    "threatgate-backup.timer"
    "threatgate-misp-sync.service"
    "threatgate-misp-sync.timer"
)

# ── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║         ThreatGate — Full Uninstaller                   ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

info "This will remove ThreatGate completely:"
echo "    - All systemd services and timers"
echo "    - All running ThreatGate processes"
echo "    - Application directory: ${APP_DIR} (code, venv, database, everything)"
echo "    - System user '${APP_USER}' and group '${APP_GROUP}'"
if $DO_BACKUP; then
    echo ""
    echo -e "    ${GREEN}✓${NC} Data backup will be saved to: ${BACKUP_DIR}"
else
    echo ""
    echo -e "    ${RED}✗${NC} All data will be permanently deleted (use --backup to save first)"
fi
echo ""

# ── Confirmation ────────────────────────────────────────────────────────────
if ! $SKIP_CONFIRM; then
    read -p "Continue and remove everything? [y/N] " -n 1 -r
    echo ""
    [[ ! $REPLY =~ ^[Yy]$ ]] && { info "Aborted."; exit 0; }
fi

# ── 1. Stop services ────────────────────────────────────────────────────────
info "Stopping ThreatGate services..."

for unit in "${ALL_UNITS[@]}"; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl stop "$unit" 2>/dev/null || true
    fi
done
ok "Services stopped."

# ── 2. Disable services ─────────────────────────────────────────────────────
info "Disabling systemd units..."

for unit in "${ALL_UNITS[@]}"; do
    systemctl disable "$unit" 2>/dev/null || true
done
ok "Services disabled."

# ── 3. Kill orphan processes ────────────────────────────────────────────────
info "Checking for leftover ThreatGate processes..."

KILLED=0
# Kill gunicorn workers running from /opt/threatgate
if pgrep -f "${APP_DIR}/venv/bin/gunicorn" &>/dev/null; then
    pkill -f "${APP_DIR}/venv/bin/gunicorn" 2>/dev/null || true
    KILLED=$((KILLED + 1))
fi
# Kill http_redirect.py if running
if pgrep -f "${APP_DIR}/http_redirect.py" &>/dev/null; then
    pkill -f "${APP_DIR}/http_redirect.py" 2>/dev/null || true
    KILLED=$((KILLED + 1))
fi
# Kill any remaining processes owned by the app user
if id "${APP_USER}" &>/dev/null; then
    if pgrep -u "${APP_USER}" &>/dev/null; then
        pkill -u "${APP_USER}" 2>/dev/null || true
        sleep 1
        # Force-kill if still running
        pkill -9 -u "${APP_USER}" 2>/dev/null || true
        KILLED=$((KILLED + 1))
    fi
fi

if [[ $KILLED -gt 0 ]]; then
    ok "Killed leftover processes."
else
    ok "No orphan processes found."
fi

# ── 4. Optional backup ──────────────────────────────────────────────────────
if $DO_BACKUP && [[ -d "${DATA_DIR}" ]]; then
    info "Backing up data to ${BACKUP_DIR}..."
    mkdir -p "${BACKUP_DIR}"
    cp -a "${DATA_DIR}/." "${BACKUP_DIR}/" 2>/dev/null || true
    echo "ThreatGate data backup" > "${BACKUP_DIR}/MANIFEST.txt"
    echo "Date: $(date)" >> "${BACKUP_DIR}/MANIFEST.txt"
    echo "Source: ${DATA_DIR}" >> "${BACKUP_DIR}/MANIFEST.txt"
    echo "" >> "${BACKUP_DIR}/MANIFEST.txt"
    echo "Contents:" >> "${BACKUP_DIR}/MANIFEST.txt"
    ls -laR "${BACKUP_DIR}" >> "${BACKUP_DIR}/MANIFEST.txt" 2>/dev/null
    ok "Backup saved: ${BACKUP_DIR}"
fi

# ── 5. Remove systemd unit files and override directories ──────────────────
info "Removing systemd unit files..."

for unit in "${ALL_UNITS[@]}"; do
    unit_file="/etc/systemd/system/${unit}"
    if [[ -f "$unit_file" ]]; then
        rm -f "$unit_file"
    fi
    # Remove override directories (e.g. /etc/systemd/system/threatgate.service.d/)
    override_dir="/etc/systemd/system/${unit}.d"
    if [[ -d "$override_dir" ]]; then
        rm -rf "$override_dir"
        ok "Removed override dir: ${override_dir}"
    fi
done

systemctl daemon-reload
# Clear stale "failed" entries from systemd
systemctl reset-failed 2>/dev/null || true
ok "Systemd units removed and daemon reloaded."

# ── 6. Remove entire application directory ──────────────────────────────────
info "Removing application directory..."

if [[ -d "${APP_DIR}" ]]; then
    rm -rf "${APP_DIR}"
    ok "Removed: ${APP_DIR}"
else
    info "Application directory not found (already removed): ${APP_DIR}"
fi

# ── 7. Remove system user and group ───────────────────────────────────────────
info "Removing system user and group..."

if id "${APP_USER}" &>/dev/null; then
    userdel "${APP_USER}" 2>/dev/null || true
    ok "User '${APP_USER}' removed."
else
    info "User '${APP_USER}' not found (already removed)."
fi

if getent group "${APP_GROUP}" &>/dev/null; then
    groupdel "${APP_GROUP}" 2>/dev/null || true
    ok "Group '${APP_GROUP}' removed."
else
    info "Group '${APP_GROUP}' not found (already removed)."
fi

# ── 8. Post-removal verification ──────────────────────────────────────────────
info "Verifying complete removal..."

LEFTOVERS=0

if [[ -d "${APP_DIR}" ]]; then
    warn "Application directory still exists: ${APP_DIR}"
    LEFTOVERS=$((LEFTOVERS + 1))
fi

if id "${APP_USER}" &>/dev/null 2>&1; then
    warn "User '${APP_USER}' still exists"
    LEFTOVERS=$((LEFTOVERS + 1))
fi

for unit in "${ALL_UNITS[@]}"; do
    if [[ -f "/etc/systemd/system/${unit}" ]]; then
        warn "Unit file still present: /etc/systemd/system/${unit}"
        LEFTOVERS=$((LEFTOVERS + 1))
    fi
done

if pgrep -f "${APP_DIR}" &>/dev/null 2>&1; then
    warn "Processes still referencing ${APP_DIR}"
    LEFTOVERS=$((LEFTOVERS + 1))
fi

if [[ $LEFTOVERS -eq 0 ]]; then
    ok "Verification passed — system is clean."
else
    warn "${LEFTOVERS} leftover(s) detected. Manual cleanup may be needed."
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         ThreatGate — Uninstall Complete                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

info "Removed:"
echo "    - All systemd services, timers, and override directories"
echo "    - All ThreatGate processes"
echo "    - ${APP_DIR}/ (application code, templates, static, Python venv)"
echo "    - ${DATA_DIR}/threatgate.db (SQLite database)"
echo "    - ${DATA_DIR}/Main/ (IOC files)"
echo "    - ${DATA_DIR}/YARA/ and YARA_pending/ (YARA rules)"
echo "    - ${DATA_DIR}/ssl/ (SSL certificates)"
echo "    - ${DATA_DIR}/backups/ (local backups)"
echo "    - ${DATA_DIR}/audit_cef.log (CEF audit logs, if present)"
echo "    - User: ${APP_USER}  |  Group: ${APP_GROUP}"
echo ""

if $DO_BACKUP && [[ -d "${BACKUP_DIR}" ]]; then
    info "Data backup preserved at: ${BACKUP_DIR}"
    echo "    To inspect: ls -la ${BACKUP_DIR}"
    echo "    To restore: sudo ./setup.sh && sudo cp -a ${BACKUP_DIR}/. /opt/threatgate/data/"
    echo ""
fi

info "Reinstall: sudo ./setup.sh   or   sudo ./setup.sh --offline"
echo ""
