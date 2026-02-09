#!/usr/bin/env bash
# ============================================================================
#  ThreatGate — Offline Package Builder (run on Dev Machine)
# ============================================================================
#  Creates a self-contained 'threatgate_installer.zip' that can be
#  transferred to an air-gapped production server.
#
#  Usage:  ./package_offline.sh
#  Output: ./threatgate_installer.zip
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
OUTPUT_ZIP="${SCRIPT_DIR}/threatgate_installer.zip"

# ── Sanity checks ──────────────────────────────────────────────────────────
[[ -f "${SCRIPT_DIR}/app.py" ]]           || fail "app.py not found. Run this from the project root."
[[ -f "${SCRIPT_DIR}/requirements.txt" ]] || fail "requirements.txt not found."
command -v pip3 &>/dev/null || command -v pip &>/dev/null || fail "pip is not installed."
command -v zip  &>/dev/null || fail "zip is not installed (apt install zip)."

PIP_CMD="pip3"
command -v pip3 &>/dev/null || PIP_CMD="pip"

# ── Clean previous build ───────────────────────────────────────────────────
info "Cleaning previous build artifacts..."
rm -rf "${DIST_DIR}" "${OUTPUT_ZIP}"
mkdir -p "${DIST_DIR}"

# ── 1. Download wheels ─────────────────────────────────────────────────────
info "Downloading Python wheels for offline install..."
mkdir -p "${DIST_DIR}/packages"
$PIP_CMD download -d "${DIST_DIR}/packages" -r "${SCRIPT_DIR}/requirements.txt"
$PIP_CMD download -d "${DIST_DIR}/packages" gunicorn
ok "Wheels downloaded to dist/packages/"

# ── 2. Copy application code ───────────────────────────────────────────────
info "Copying application files..."

cp "${SCRIPT_DIR}/app.py"            "${DIST_DIR}/"
cp "${SCRIPT_DIR}/cleaner.py"        "${DIST_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt"  "${DIST_DIR}/"
cp "${SCRIPT_DIR}/setup.sh"          "${DIST_DIR}/"
chmod +x "${DIST_DIR}/setup.sh"

# Systemd units
cp "${SCRIPT_DIR}/threatgate.service"          "${DIST_DIR}/"
cp "${SCRIPT_DIR}/threatgate-cleaner.service"  "${DIST_DIR}/"
cp "${SCRIPT_DIR}/threatgate-cleaner.timer"    "${DIST_DIR}/"

# Templates
mkdir -p "${DIST_DIR}/templates"
cp -r "${SCRIPT_DIR}/templates/"* "${DIST_DIR}/templates/"

# Static assets
mkdir -p "${DIST_DIR}/static"
cp -r "${SCRIPT_DIR}/static/"* "${DIST_DIR}/static/"

# Optional data files
mkdir -p "${DIST_DIR}/data"
[[ -f "${SCRIPT_DIR}/data/GeoLite2-City.mmdb" ]] && \
    cp "${SCRIPT_DIR}/data/GeoLite2-City.mmdb" "${DIST_DIR}/data/"
[[ -f "${SCRIPT_DIR}/data/allowlist.txt" ]] && \
    cp "${SCRIPT_DIR}/data/allowlist.txt" "${DIST_DIR}/data/"

ok "Application files copied."

# ── 3. Create zip archive ──────────────────────────────────────────────────
info "Creating zip archive..."
cd "${DIST_DIR}"
zip -r "${OUTPUT_ZIP}" . -x "*.pyc" "__pycache__/*"
cd "${SCRIPT_DIR}"
ok "Archive created: ${OUTPUT_ZIP}"

# ── 4. Cleanup ──────────────────────────────────────────────────────────────
info "Removing temporary dist/ folder..."
rm -rf "${DIST_DIR}"
ok "Cleanup complete."

# ── Summary ─────────────────────────────────────────────────────────────────
SIZE=$(du -h "${OUTPUT_ZIP}" | awk '{print $1}')
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Offline Package Ready                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
info "File : ${OUTPUT_ZIP}"
info "Size : ${SIZE}"
echo ""
info "Deployment on target server:"
info "  1. Copy the zip to the server"
info "  2. unzip threatgate_installer.zip -d threatgate_install"
info "  3. cd threatgate_install"
info "  4. sudo ./setup.sh --offline"
echo ""
