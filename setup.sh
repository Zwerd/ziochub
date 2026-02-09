#!/usr/bin/env bash
# ============================================================================
#  ThreatGate — Production Installer (Linux)
# ============================================================================
#  Usage:
#    sudo ./setup.sh              # Online install  (pip fetches from PyPI)
#    sudo ./setup.sh --offline    # Offline install  (uses local wheels in ./packages)
# ============================================================================
set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Pre-flight ──────────────────────────────────────────────────────────────
OFFLINE=false
for arg in "$@"; do
    [[ "$arg" == "--offline" ]] && OFFLINE=true
done

[[ $EUID -ne 0 ]] && fail "This script must be run as root (sudo ./setup.sh)"

info "ThreatGate Production Installer"
info "Mode: $( $OFFLINE && echo 'OFFLINE (local wheels)' || echo 'ONLINE (pip from PyPI)' )"
echo ""

# ── Constants ───────────────────────────────────────────────────────────────
APP_USER="threatgate"
APP_GROUP="threatgate"
APP_DIR="/opt/threatgate"
DATA_DIR="${APP_DIR}/data"
VENV_DIR="${APP_DIR}/venv"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── 1. System user & group ─────────────────────────────────────────────────
info "Creating system user '${APP_USER}'..."
if id "${APP_USER}" &>/dev/null; then
    ok "User '${APP_USER}' already exists."
else
    groupadd --system "${APP_GROUP}" 2>/dev/null || true
    useradd  --system --gid "${APP_GROUP}" \
             --home-dir "${APP_DIR}" --shell /usr/sbin/nologin \
             "${APP_USER}"
    ok "User '${APP_USER}' created."
fi

# ── 2. Directory structure ──────────────────────────────────────────────────
info "Setting up directories..."
mkdir -p "${APP_DIR}" "${DATA_DIR}" "${DATA_DIR}/Main" "${DATA_DIR}/YARA"
ok "Directories ready: ${APP_DIR}"

# ── 3. Copy application files ──────────────────────────────────────────────
info "Copying application files..."

cp "${SCRIPT_DIR}/app.py"           "${APP_DIR}/"
cp "${SCRIPT_DIR}/cleaner.py"       "${APP_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"

# Templates
mkdir -p "${APP_DIR}/templates"
cp -r "${SCRIPT_DIR}/templates/"* "${APP_DIR}/templates/"

# Static assets
mkdir -p "${APP_DIR}/static"
cp -r "${SCRIPT_DIR}/static/"* "${APP_DIR}/static/"

# Copy GeoIP database if present
if [[ -f "${SCRIPT_DIR}/data/GeoLite2-City.mmdb" ]]; then
    cp "${SCRIPT_DIR}/data/GeoLite2-City.mmdb" "${DATA_DIR}/"
    ok "GeoIP database copied."
fi

# Copy allowlist if present
if [[ -f "${SCRIPT_DIR}/data/allowlist.txt" ]]; then
    cp "${SCRIPT_DIR}/data/allowlist.txt" "${DATA_DIR}/"
    ok "Allowlist copied."
fi

ok "Application files copied."

# ── 4. Permissions ──────────────────────────────────────────────────────────
info "Setting ownership & permissions..."
chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"
chmod 750 "${APP_DIR}"
chmod -R u+rwX,g+rX,o-rwx "${DATA_DIR}"
ok "Permissions set (${APP_USER}:${APP_GROUP})."

# ── 5. Virtual environment & dependencies ───────────────────────────────────
info "Creating Python virtual environment..."
python3 -m venv "${VENV_DIR}"
chown -R "${APP_USER}:${APP_GROUP}" "${VENV_DIR}"
ok "venv created at ${VENV_DIR}."

info "Installing dependencies..."
if $OFFLINE; then
    PACKAGES_DIR="${SCRIPT_DIR}/packages"
    if [[ ! -d "${PACKAGES_DIR}" ]]; then
        fail "Offline mode requires a 'packages/' directory with wheel files next to this script."
    fi
    "${VENV_DIR}/bin/pip" install --no-index --find-links="${PACKAGES_DIR}" \
        --upgrade pip 2>/dev/null || true
    "${VENV_DIR}/bin/pip" install --no-index --find-links="${PACKAGES_DIR}" \
        gunicorn -r "${APP_DIR}/requirements.txt"
else
    "${VENV_DIR}/bin/pip" install --upgrade pip 2>/dev/null || true
    "${VENV_DIR}/bin/pip" install gunicorn -r "${APP_DIR}/requirements.txt"
fi
ok "Dependencies installed."

# Fix venv ownership after pip installs
chown -R "${APP_USER}:${APP_GROUP}" "${VENV_DIR}"

# ── 6. Systemd services ────────────────────────────────────────────────────
info "Installing systemd units..."

cp "${SCRIPT_DIR}/threatgate.service"          /etc/systemd/system/
cp "${SCRIPT_DIR}/threatgate-cleaner.service"  /etc/systemd/system/
cp "${SCRIPT_DIR}/threatgate-cleaner.timer"    /etc/systemd/system/

systemctl daemon-reload

systemctl enable threatgate.service
systemctl enable threatgate-cleaner.timer

systemctl restart threatgate.service
systemctl start   threatgate-cleaner.timer

ok "Systemd units installed & started."

# ── 7. Summary ──────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         ThreatGate — Installation Complete              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Application path : ${APP_DIR}"
info "Data directory   : ${DATA_DIR}"
info "Service user     : ${APP_USER}"
echo ""

systemctl --no-pager status threatgate.service || true

echo ""
info "Web UI available at: http://$(hostname -I | awk '{print $1}'):8000"
info ""
info "Useful commands:"
info "  journalctl -u threatgate -f          # Live logs"
info "  systemctl restart threatgate          # Restart app"
info "  systemctl status threatgate-cleaner.timer  # Cleaner schedule"
echo ""
