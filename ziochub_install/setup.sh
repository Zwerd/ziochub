#!/usr/bin/env bash
# ============================================================================
#  ZIoCHub — Production Installer (Linux)
# ============================================================================
#  Installs ZIoCHub as a systemd-managed service on a Linux server.
#  Supports online, offline, and upgrade modes.
#
#  Usage:
#    sudo ./setup.sh              # Online install  (pip fetches from PyPI)
#    sudo ./setup.sh --offline    # Offline install  (uses local wheels in ./packages)
#    sudo ./setup.sh --upgrade    # Upgrade existing installation
#    sudo ./setup.sh --help       # Full help with steps and paths
#
#  Installs to /opt/ziochub with data in /opt/ziochub/data/
#  Creates systemd services for the app, cleaner, backup, MISP.
#  Auto-generates a self-signed SSL certificate if openssl is available.
#  HTTPS port: 8443 (default), or 443 / custom. Port 443 requires setcap; see security note in installer.
#
#  Updated: 2025-03-11
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
    echo -e "${CYAN}ZIoCHub — Production Installer${NC}"
    echo ""
    echo "Usage:  sudo ./setup.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --offline     Install from local wheel files in ./packages/ directory"
    echo "                (no internet required). Use package_offline.sh to prepare."
    echo "  --upgrade     Upgrade an existing installation. Preserves database,"
    echo "                IOC files, YARA rules, and SSL certificates."
    echo "  --help, -h    Show this help message and exit."
    echo ""
    echo "Modes:"
    echo "  Fresh install (online)    sudo ./setup.sh"
    echo "  Fresh install (offline)   sudo ./setup.sh --offline"
    echo "  Upgrade (online)          sudo ./setup.sh --upgrade"
    echo "  Upgrade (offline)         sudo ./setup.sh --upgrade --offline"
    echo ""
    echo "What the installer does:"
    echo "  1. Runs pre-flight checks (Python, systemd, openssl, required files)"
    echo "  2. Creates system user 'ziochub'"
    echo "  3. Copies application files to /opt/ziochub"
    echo "  4. Creates Python venv and installs dependencies"
    echo "  5. Initializes the SQLite database"
    echo "  6. Generates a self-signed SSL certificate (requires openssl)"
    echo "  7. Asks which HTTPS port to use (8443 default, or 443 with security note)"
    echo "  8. Installs and enables systemd services:"
    echo "       - ziochub.service"
    echo "       - ziochub-cleaner.service, ziochub-cleaner.timer"
    echo "       - ziochub-backup.service, ziochub-backup.timer"
    echo "       - ziochub-misp-sync.service, ziochub-misp-sync.timer"
    echo ""
    echo "HTTPS port:"
    echo "  Default is 8443. You can choose 443 (requires setcap; see security note in installer)"
    echo "  or a custom port. Port is stored in /opt/ziochub/data/ziochub.env (ZIOCHUB_PORT)."
    echo ""
    echo "Paths:"
    echo "  Application   /opt/ziochub"
    echo "  Database      /opt/ziochub/data/ziochub.db"
    echo "  IOC files     /opt/ziochub/data/Main/"
    echo "  YARA rules    /opt/ziochub/data/YARA/"
    echo "  SSL certs     /opt/ziochub/data/ssl/"
    echo "  Port config   /opt/ziochub/data/ziochub.env"
    echo "  Backups       /opt/ziochub/data/backups/"
    echo "  Documentation /opt/ziochub/docs/ (optional; e.g. DXL integration)"
    echo ""
    exit 0
}

# ── Pre-flight ──────────────────────────────────────────────────────────────
OFFLINE=false
UPGRADE=false
for arg in "$@"; do
    [[ "$arg" == "--help" || "$arg" == "-h" ]] && show_help
    [[ "$arg" == "--offline" ]] && OFFLINE=true
    [[ "$arg" == "--upgrade" ]] && UPGRADE=true
done

[[ $EUID -ne 0 ]] && fail "This script must be run as root (sudo ./setup.sh)"

# ── Constants ───────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_USER="ziochub"
APP_GROUP="ziochub"
APP_DIR="/opt/ziochub"
DATA_DIR="${APP_DIR}/data"
VENV_DIR="${APP_DIR}/venv"

# ── Fix permissions (ZIP extraction may strip +x from .sh files) ───────────
chmod +x "${SCRIPT_DIR}/"*.sh 2>/dev/null || true

# ── Must NOT run from installed dir (upgrade would copy old over old) ───────
SCRIPT_CANON=$(readlink -f "${SCRIPT_DIR}" 2>/dev/null || realpath "${SCRIPT_DIR}" 2>/dev/null || echo "${SCRIPT_DIR}")
APP_CANON=$(readlink -f "${APP_DIR}" 2>/dev/null || realpath "${APP_DIR}" 2>/dev/null || echo "${APP_DIR}")
if [[ "${SCRIPT_CANON}" == "${APP_CANON}" ]] || [[ "${SCRIPT_DIR}" == "${APP_DIR}" ]]; then
    fail "Do not run setup.sh from the installed directory (${APP_DIR})." \
         "Extract the installer ZIP to a separate folder (e.g. ziochub_install), then run: cd ziochub_install && sudo ./setup.sh --upgrade --offline"
fi

# ════════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT CHECKS — Verify all requirements before starting installation
# ════════════════════════════════════════════════════════════════════════════
echo ""
info "Running pre-flight checks..."
echo ""

PREFLIGHT_ERRORS=()
PREFLIGHT_WARNINGS=()

# ── 1. System commands ──────────────────────────────────────────────────────
# Check Python3
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 --version 2>&1)
    ok "Python3 found: ${PY_VERSION}"
else
    PREFLIGHT_ERRORS+=("Python3 is not installed. Install with: apt install python3")
fi

# Check Python venv module
if python3 -m venv --help &>/dev/null 2>&1; then
    ok "Python venv module available"
else
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3.x")
    PREFLIGHT_ERRORS+=("Python venv module not available.")
    PREFLIGHT_ERRORS+=("  Install with: sudo apt-get install python3-venv")
    PREFLIGHT_ERRORS+=("  Or for your Python version: sudo apt-get install python${PY_VER}-venv")
fi

# Check systemctl
if command -v systemctl &>/dev/null; then
    ok "systemctl found"
else
    PREFLIGHT_ERRORS+=("systemctl not found. This installer requires systemd.")
fi

# ── 2. Required application files ───────────────────────────────────────────
REQUIRED_FILES=(
    "app.py"
    "cleaner.py"
    "constants.py"
    "models.py"
    "extensions.py"
    "misp_settings.py"
    "start.sh"
    "requirements.txt"
    "ziochub.service"
    "ziochub-cleaner.service"
    "ziochub-cleaner.timer"
)

MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "${SCRIPT_DIR}/${file}" ]]; then
        MISSING_FILES+=("$file")
    fi
done

if [[ ${#MISSING_FILES[@]} -eq 0 ]]; then
    ok "All required application files present"
else
    PREFLIGHT_ERRORS+=("Missing required files: ${MISSING_FILES[*]}")
fi

# ── 3. Required directories ─────────────────────────────────────────────────
REQUIRED_DIRS=("templates" "static" "utils" "routes")
MISSING_DIRS=()
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "${SCRIPT_DIR}/${dir}" ]]; then
        MISSING_DIRS+=("$dir/")
    fi
done

if [[ ${#MISSING_DIRS[@]} -eq 0 ]]; then
    ok "All required directories present"
else
    PREFLIGHT_ERRORS+=("Missing required directories: ${MISSING_DIRS[*]}")
fi

# ── 4. Offline-specific checks ──────────────────────────────────────────────
if $OFFLINE; then
    # Check packages directory (.whl, .tar.gz, .zip are all valid pip formats)
    if [[ -d "${SCRIPT_DIR}/packages" ]]; then
        PKG_COUNT=$(find "${SCRIPT_DIR}/packages" -maxdepth 1 -type f \( -name "*.whl" -o -name "*.tar.gz" -o -name "*.zip" \) 2>/dev/null | wc -l)
        if [[ $PKG_COUNT -gt 0 ]]; then
            ok "Offline packages found: ${PKG_COUNT} package files"
        else
            PREFLIGHT_ERRORS+=("packages/ directory exists but contains no pip-installable files (.whl, .tar.gz)")
        fi
    else
        PREFLIGHT_ERRORS+=("Offline mode requires 'packages/' directory with pip packages")
        PREFLIGHT_ERRORS+=("  Build with: ./package_offline.sh (or manually: pip download -d packages/ -r requirements.txt gunicorn pip setuptools wheel)")
    fi

    # Check system-packages (warning only)
    if [[ -d "${SCRIPT_DIR}/system-packages" ]]; then
        DEB_COUNT=$(find "${SCRIPT_DIR}/system-packages" -maxdepth 1 -type f -name "*.deb" 2>/dev/null | wc -l)
        if [[ $DEB_COUNT -gt 0 ]]; then
            ok "System packages found: ${DEB_COUNT} deb files"
        fi
    fi
else
    # Online mode - check internet connectivity
    if ping -c 1 -W 2 pypi.org &>/dev/null 2>&1; then
        ok "Internet connectivity: PyPI reachable"
    else
        PREFLIGHT_WARNINGS+=("Cannot reach pypi.org. If pip install fails, use --offline mode.")
    fi
fi

# ── 5. Optional tools & files ────────────────────────────────────────────────
if command -v openssl &>/dev/null; then
    ok "OpenSSL found (SSL certificate will be auto-generated)"
else
    PREFLIGHT_WARNINGS+=("openssl not found — SSL certificate will NOT be generated. Install openssl to enable HTTPS.")
fi

if [[ -f "${SCRIPT_DIR}/data/GeoLite2-City.mmdb" ]]; then
    ok "GeoIP database found"
else
    PREFLIGHT_WARNINGS+=("GeoIP database not found (optional). IP geolocation will be disabled.")
fi

# ── 6. Disk space check ─────────────────────────────────────────────────────
AVAILABLE_SPACE=$(df -BM /opt 2>/dev/null | awk 'NR==2 {gsub("M",""); print $4}')
if [[ -n "$AVAILABLE_SPACE" ]] && [[ "$AVAILABLE_SPACE" -gt 500 ]]; then
    ok "Disk space: ${AVAILABLE_SPACE}MB available in /opt"
elif [[ -n "$AVAILABLE_SPACE" ]]; then
    PREFLIGHT_WARNINGS+=("Low disk space: ${AVAILABLE_SPACE}MB in /opt (recommended: 500MB+)")
fi

# ════════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT SUMMARY
# ════════════════════════════════════════════════════════════════════════════
echo ""

# Show warnings
if [[ ${#PREFLIGHT_WARNINGS[@]} -gt 0 ]]; then
    warn "Warnings (installation will continue):"
    for warning in "${PREFLIGHT_WARNINGS[@]}"; do
        echo -e "    ${YELLOW}⚠${NC}  $warning"
    done
    echo ""
fi

# Show errors and abort if any
if [[ ${#PREFLIGHT_ERRORS[@]} -gt 0 ]]; then
    echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║         Pre-flight Check FAILED                         ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}The following issues must be fixed before installation:${NC}"
    echo ""
    for error in "${PREFLIGHT_ERRORS[@]}"; do
        echo -e "    ${RED}✗${NC}  $error"
    done
    echo ""
    info "Fix the issues above and run setup.sh again."
    exit 1
fi

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Pre-flight Check PASSED                         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Detect existing installation ────────────────────────────────────────────
EXISTING_INSTALL=false
if [[ -d "${APP_DIR}" ]] && [[ -f "${APP_DIR}/app.py" ]]; then
    EXISTING_INSTALL=true
fi

if $EXISTING_INSTALL && ! $UPGRADE; then
    echo ""
    warn "Existing ZIoCHub installation detected at ${APP_DIR}"
    echo ""
    info "Options:"
    echo "    1. Run with --upgrade to update the existing installation"
    echo "    2. Run uninstall.sh first to remove the old installation"
    echo ""
    read -p "Continue with upgrade? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        UPGRADE=true
    else
        info "Aborted. Use: sudo ./setup.sh --upgrade"
        exit 0
    fi
fi

# ── Banner ──────────────────────────────────────────────────────────────────
echo ""
if $UPGRADE; then
    info "ZIoCHub Production Installer (UPGRADE MODE)"
else
    info "ZIoCHub Production Installer (FRESH INSTALL)"
fi
info "Mode: $( $OFFLINE && echo 'OFFLINE (local wheels)' || echo 'ONLINE (pip from PyPI)' )"
echo ""

# ── 0. Stop services if upgrading ──────────────────────────────────────────
if $UPGRADE; then
    info "Stopping existing services for upgrade..."
    systemctl stop ziochub.service 2>/dev/null || true
    systemctl stop ziochub-redirect.service 2>/dev/null || true
    systemctl stop ziochub-cleaner.timer 2>/dev/null || true
    systemctl stop ziochub-cleaner.service 2>/dev/null || true
    systemctl stop ziochub-backup.timer 2>/dev/null || true
    systemctl stop ziochub-backup.service 2>/dev/null || true
    systemctl stop ziochub-misp-sync.timer 2>/dev/null || true
    systemctl stop ziochub-misp-sync.service 2>/dev/null || true
    ok "Services stopped."
fi

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
mkdir -p "${APP_DIR}" "${DATA_DIR}" "${DATA_DIR}/Main" "${DATA_DIR}/YARA" "${DATA_DIR}/YARA_pending" "${DATA_DIR}/backups"
ok "Directories ready: ${APP_DIR}"

# ── 3. Copy application files (overwrites existing on upgrade) ─────────────
info "Copying application files..."

cp "${SCRIPT_DIR}/app.py"           "${APP_DIR}/"
cp "${SCRIPT_DIR}/cleaner.py"       "${APP_DIR}/"
cp "${SCRIPT_DIR}/start.sh"         "${APP_DIR}/"
chmod +x "${APP_DIR}/start.sh"
[[ -f "${SCRIPT_DIR}/misp_sync_job.py" ]] && cp "${SCRIPT_DIR}/misp_sync_job.py" "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/misp_settings.py" ]] && cp "${SCRIPT_DIR}/misp_settings.py" "${APP_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/requirements-offline.txt" ]] && cp "${SCRIPT_DIR}/requirements-offline.txt" "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/config.py" ]]       && cp "${SCRIPT_DIR}/config.py"       "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/constants.py" ]]    && cp "${SCRIPT_DIR}/constants.py"    "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/extensions.py" ]]   && cp "${SCRIPT_DIR}/extensions.py"   "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/models.py" ]]       && cp "${SCRIPT_DIR}/models.py"       "${APP_DIR}/"
[[ -d "${SCRIPT_DIR}/utils" ]]           && cp -r "${SCRIPT_DIR}/utils"        "${APP_DIR}/"
[[ -d "${SCRIPT_DIR}/routes" ]]          && cp -r "${SCRIPT_DIR}/routes"       "${APP_DIR}/"

# Admin/lab scripts
[[ -f "${SCRIPT_DIR}/reset_data.py" ]]      && cp "${SCRIPT_DIR}/reset_data.py"      "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/create_lab_users.py" ]] && cp "${SCRIPT_DIR}/create_lab_users.py" "${APP_DIR}/"

# scripts/ (reset_admin_password.py, etc.)
if [[ -d "${SCRIPT_DIR}/scripts" ]]; then
    mkdir -p "${APP_DIR}/scripts"
    cp -r "${SCRIPT_DIR}/scripts/"* "${APP_DIR}/scripts/" 2>/dev/null || true
    ok "scripts/ copied."
fi

# Templates
mkdir -p "${APP_DIR}/templates"
cp -r "${SCRIPT_DIR}/templates/"* "${APP_DIR}/templates/"

# Static assets (full tree; ensure css/ and critical CSS files are present)
mkdir -p "${APP_DIR}/static"
cp -r "${SCRIPT_DIR}/static/"* "${APP_DIR}/static/" 2>/dev/null || true
[[ -d "${SCRIPT_DIR}/static/css" ]] && mkdir -p "${APP_DIR}/static/css" && cp -r "${SCRIPT_DIR}/static/css/"* "${APP_DIR}/static/css/" 2>/dev/null || true
# Explicit copy of critical CSS so upgrade always gets them if present in installer
[[ -f "${SCRIPT_DIR}/static/css/tailwind-built.css" ]] && cp "${SCRIPT_DIR}/static/css/tailwind-built.css" "${APP_DIR}/static/css/" && ok "tailwind-built.css copied."
[[ -f "${SCRIPT_DIR}/static/css/style.css" ]]         && cp "${SCRIPT_DIR}/static/css/style.css" "${APP_DIR}/static/css/"         && ok "style.css copied."
if [[ ! -f "${APP_DIR}/static/css/tailwind-built.css" ]]; then
    warn "static/css/tailwind-built.css missing after copy. Build it (npm run build:css) and add to installer, or UI may look broken."
fi

# Backup script (offline-safe, local only)
if [[ -f "${SCRIPT_DIR}/backup_ziochub.sh" ]]; then
    cp "${SCRIPT_DIR}/backup_ziochub.sh" "${APP_DIR}/"
    chmod +x "${APP_DIR}/backup_ziochub.sh"
    ok "Backup script installed."
fi

if [[ -f "${SCRIPT_DIR}/uninstall.sh" ]]; then
    cp "${SCRIPT_DIR}/uninstall.sh" "${APP_DIR}/"
    chmod +x "${APP_DIR}/uninstall.sh"
fi

# Copy GeoIP database if present
if [[ -f "${SCRIPT_DIR}/data/GeoLite2-City.mmdb" ]]; then
    cp "${SCRIPT_DIR}/data/GeoLite2-City.mmdb" "${DATA_DIR}/"
    ok "GeoIP database copied."
fi

# Copy allowlist if present (backup existing first)
if [[ -f "${SCRIPT_DIR}/data/allowlist.txt" ]]; then
    if [[ -f "${DATA_DIR}/allowlist.txt" ]]; then
        ALLOWLIST_BACKUP="${DATA_DIR}/allowlist.txt.bak.$(date +%Y%m%d_%H%M%S)"
        cp "${DATA_DIR}/allowlist.txt" "${ALLOWLIST_BACKUP}"
        warn "Existing allowlist backed up to: ${ALLOWLIST_BACKUP}"
    fi
    cp "${SCRIPT_DIR}/data/allowlist.txt" "${DATA_DIR}/"
    ok "Allowlist copied."
fi

# Copy org_domains config if present (used by sanity checks for own-domain detection)
if [[ -f "${SCRIPT_DIR}/data/org_domains.txt" ]]; then
    cp "${SCRIPT_DIR}/data/org_domains.txt" "${DATA_DIR}/"
    ok "Organization domains config copied."
fi

# Optional documentation (e.g. DXL integration, deployment notes)
if [[ -d "${SCRIPT_DIR}/docs" ]]; then
    mkdir -p "${APP_DIR}/docs"
    cp -r "${SCRIPT_DIR}/docs/"* "${APP_DIR}/docs/" 2>/dev/null || true
    ok "Documentation (docs/) copied."
fi

ok "Application files copied."

# ── 4. Permissions ──────────────────────────────────────────────────────────
info "Setting ownership & permissions..."
chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"
chmod 750 "${APP_DIR}"
chmod -R u+rwX,g+rX,o-rwx "${DATA_DIR}"
ok "Permissions set (${APP_USER}:${APP_GROUP})."

# ── 5. Virtual environment & dependencies ───────────────────────────────────
# Remove old/corrupted venv if exists (ensures clean state)
if [[ -d "${VENV_DIR}" ]]; then
    info "Removing existing virtual environment..."
    rm -rf "${VENV_DIR}"
    ok "Old venv removed."
fi

info "Creating Python virtual environment..."
if ! python3 -m venv "${VENV_DIR}" 2>/dev/null; then
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3.x")
    echo ""
    fail "Failed to create virtual environment. Python venv module is not available." \
         "" \
         "To fix this, install the python3-venv package:" \
         "  sudo apt-get install python3-venv" \
         "" \
         "Or for your specific Python version (${PY_VER}):" \
         "  sudo apt-get install python${PY_VER}-venv" \
         "" \
         "After installing, run this installer again."
fi
chown -R "${APP_USER}:${APP_GROUP}" "${VENV_DIR}"
ok "venv created at ${VENV_DIR}."

info "Installing dependencies..."
if $OFFLINE; then
    PACKAGES_DIR="${SCRIPT_DIR}/packages"
    if [[ ! -d "${PACKAGES_DIR}" ]]; then
        fail "Offline mode requires a 'packages/' directory with pip packages next to this script." \
             "Build the offline package first: ./package_offline.sh"
    fi
    # 1. Upgrade pip from local packages (best-effort)
    "${VENV_DIR}/bin/pip" install --no-index --find-links="${PACKAGES_DIR}" \
        --upgrade pip 2>/dev/null || true
    # 2. Install build tools (needed if any package is a .tar.gz source dist)
    "${VENV_DIR}/bin/pip" install --no-index --find-links="${PACKAGES_DIR}" \
        setuptools wheel 2>/dev/null || true
    # 3. Install gunicorn + application dependencies (full requirements first; fallback to core without DXL)
    if ! "${VENV_DIR}/bin/pip" install --no-index --find-links="${PACKAGES_DIR}" \
        gunicorn -r "${APP_DIR}/requirements.txt"; then
        if [[ -f "${APP_DIR}/requirements-offline.txt" ]]; then
            warn "Full requirements install failed (e.g. DXL packages missing). Installing core only..."
            "${VENV_DIR}/bin/pip" install --no-index --find-links="${PACKAGES_DIR}" \
                gunicorn -r "${APP_DIR}/requirements-offline.txt" || \
                fail "Offline pip install failed. Packages may be missing or incompatible." \
                     "" \
                     "Common fixes:" \
                     "  - Rebuild the offline package: ./package_offline.sh (on a machine with internet)" \
                     "  - Or: pip download -d packages/ -r requirements.txt gunicorn pip setuptools wheel"
            warn "DXL/TIE packages were not in the offline bundle. DXL features will be disabled."
        else
            fail "Offline pip install failed. Packages may be missing or incompatible." \
                 "" \
                 "Common fixes:" \
                 "  - Rebuild the offline package on a machine with the same OS/Python version as this server" \
                 "  - Run: pip download -d packages/ -r requirements.txt gunicorn pip setuptools wheel"
        fi
    fi
else
    "${VENV_DIR}/bin/pip" install --upgrade pip 2>/dev/null || true
    "${VENV_DIR}/bin/pip" install gunicorn -r "${APP_DIR}/requirements.txt"
fi
ok "Dependencies installed."

# ── 5c. Verify Python module imports ───────────────────────────────────────
info "Verifying Python module imports..."

REQUIRED_MODULES=("constants" "models" "extensions")
MISSING_MODULES=()

for module in "${REQUIRED_MODULES[@]}"; do
    if ! "${VENV_DIR}/bin/python" -c "import ${module}" 2>/dev/null; then
        MISSING_MODULES+=("${module}")
    fi
done

if [[ ${#MISSING_MODULES[@]} -gt 0 ]]; then
    fail "Missing Python modules: ${MISSING_MODULES[*]}"
fi

# Verify utils submodules (Reports, Admin Settings, CEF logging, etc.)
REQUIRED_UTILS=("validation" "refanger" "allowlist" "feed_helpers" "yara_utils" "validation_warnings" "validation_messages" "sanity_checks" "auth" "decorators" "ldap_auth" "champs" "ioc_decode" "misp_sync" "cef_logger" "mentorship" "ambition")
MISSING_UTILS=()

for util in "${REQUIRED_UTILS[@]}"; do
    if ! "${VENV_DIR}/bin/python" -c "import utils.${util}" 2>/dev/null; then
        MISSING_UTILS+=("utils.${util}")
    fi
done

if [[ ${#MISSING_UTILS[@]} -gt 0 ]]; then
    warn "Some utils submodules may be missing: ${MISSING_UTILS[*]}"
    warn "Service may fail to start. Check package contents."
fi

ok "Python module imports verified."

# Fix venv ownership after pip installs
chown -R "${APP_USER}:${APP_GROUP}" "${VENV_DIR}"

# ── 5b. Final ownership and DB init (ensures service runs without permission issues) ─
info "Ensuring full ownership for service user..."
chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"
chmod 750 "${APP_DIR}"
chmod -R u+rwX,g+rX,o-rwx "${DATA_DIR}"
ok "Ownership and data permissions set."

info "Initializing database as ${APP_USER}..."
# Importing app runs _init_db() once at module load; avoid calling _init_db() again to prevent duplicate migration messages
if sudo -u "${APP_USER}" env PATH="${VENV_DIR}/bin:${PATH}" bash -c "cd ${APP_DIR} && python3 -c 'import app'" 2>/dev/null; then
    ok "Database initialized."
else
    warn "Database init skipped or failed (service will create on first run)."
fi

# ── 5d. SSL certificate generation ─────────────────────────────────────────
SSL_DIR="${DATA_DIR}/ssl"
mkdir -p "${SSL_DIR}"

if [[ -f "${SSL_DIR}/cert.pem" && -f "${SSL_DIR}/key.pem" ]]; then
    ok "SSL certificate already exists — skipping generation."
else
    if command -v openssl &>/dev/null; then
        info "Generating self-signed SSL certificate..."
        SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
        SERVER_HOSTNAME="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo 'localhost')"
        SAN_ENTRIES="DNS:localhost,DNS:${SERVER_HOSTNAME}"
        [[ -n "${SERVER_IP}" ]] && SAN_ENTRIES="${SAN_ENTRIES},IP:${SERVER_IP}"

        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${SSL_DIR}/key.pem" \
            -out "${SSL_DIR}/cert.pem" \
            -days 365 \
            -subj "/CN=${SERVER_HOSTNAME}/O=ZIoCHub/OU=SOC" \
            -addext "subjectAltName=${SAN_ENTRIES}" \
            2>/dev/null

        if [[ -f "${SSL_DIR}/cert.pem" && -f "${SSL_DIR}/key.pem" ]]; then
            chmod 640 "${SSL_DIR}/key.pem" "${SSL_DIR}/cert.pem"
            chown "${APP_USER}:${APP_GROUP}" "${SSL_DIR}/key.pem" "${SSL_DIR}/cert.pem"
            ok "Self-signed SSL certificate created at ${SSL_DIR}/"
            ok "  cert.pem  (valid for 365 days)"
            ok "  key.pem"
            info "SAN: ${SAN_ENTRIES}"
        else
            warn "openssl command ran but certificate files not created."
        fi
    else
        echo ""
        echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  WARNING: openssl is not installed                      ║${NC}"
        echo -e "${RED}║  SSL certificate was NOT generated.                     ║${NC}"
        echo -e "${RED}║  ZIoCHub will run on plain HTTP (port from ziochub.env). ║${NC}"
        echo -e "${RED}║                                                         ║${NC}"
        echo -e "${RED}║  To enable HTTPS later:                                 ║${NC}"
        echo -e "${RED}║    1. Install openssl:  apt install openssl             ║${NC}"
        echo -e "${RED}║    2. Generate a certificate:                           ║${NC}"
        echo -e "${RED}║       openssl req -x509 -newkey rsa:2048 -nodes \\      ║${NC}"
        echo -e "${RED}║         -keyout ${SSL_DIR}/key.pem \\${NC}"
        echo -e "${RED}║         -out ${SSL_DIR}/cert.pem \\${NC}"
        echo -e "${RED}║         -days 365 -subj '/CN=localhost'                 ║${NC}"
        echo -e "${RED}║    3. Restart: systemctl restart ziochub               ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi
fi

chown -R "${APP_USER}:${APP_GROUP}" "${SSL_DIR}" 2>/dev/null || true

# ── 5e. HTTPS port selection ───────────────────────────────────────────────
# On upgrade: preserve port from env file if present; otherwise default 8443 (no prompt)
HTTPS_PORT=""
if $UPGRADE; then
    if [[ -f "${DATA_DIR}/ziochub.env" ]] && grep -q '^ZIOCHUB_PORT=' "${DATA_DIR}/ziochub.env" 2>/dev/null; then
        HTTPS_PORT=$(grep '^ZIOCHUB_PORT=' "${DATA_DIR}/ziochub.env" | cut -d= -f2- | tr -d '\r\n' | head -1)
        if [[ -n "${HTTPS_PORT}" ]] && [[ "${HTTPS_PORT}" =~ ^[0-9]+$ ]]; then
            ok "HTTPS port preserved from previous install: ${HTTPS_PORT}"
        else
            HTTPS_PORT="8443"
        fi
    else
        HTTPS_PORT="8443"
        ok "Using default HTTPS port 8443 (edit ${DATA_DIR}/ziochub.env to change)"
    fi
fi

_port_in_use() {
    local p="$1"
    ss -tlnp 2>/dev/null | grep -q ":${p} " || true
}

_port_usage_info() {
    local p="$1"
    echo ""
    info "Port ${p} appears to be in use. Example check:"
    ss -tlnp 2>/dev/null | grep ":${p} " || true
    if command -v lsof &>/dev/null; then
        lsof -i ":${p}" 2>/dev/null || true
    fi
}

if [[ -z "${HTTPS_PORT}" ]]; then
    echo ""
    info "On which port should ZIoCHub listen for HTTPS?"
    echo "    [1] 8443 (default, recommended - no special permissions)"
    echo "    [2] 443  (standard HTTPS; requires setcap - see security note below)"
    echo "    [3] Other (enter a port number)"
    echo ""
    echo "  Security note (port 443): Binding to 443 as non-root uses setcap on the Python binary."
    echo "  From an AppSec perspective, prefer 8443 and put nginx/Caddy on 443 as reverse proxy."
    echo ""
    read -p "Choice [1/2/3] (default: 1): " -r PORT_CHOICE
    PORT_CHOICE="${PORT_CHOICE:-1}"

    case "${PORT_CHOICE}" in
        1) HTTPS_PORT="8443" ;;
        2)
            HTTPS_PORT="443"
            if _port_in_use 443; then
                echo ""
                warn "Port 443 is already in use on this system."
                _port_usage_info 443
                echo ""
                info "Use port 8443 (option 1) or put ZIoCHub behind a reverse proxy on 443."
                read -p "Continue with 443 anyway? [y/N] " -n 1 -r
                echo ""
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    info "Using port 8443 instead."
                    HTTPS_PORT="8443"
                fi
            fi
            ;;
        3)
            read -p "Enter HTTPS port (1-65535): " -r CUSTOM_PORT
            if [[ -z "${CUSTOM_PORT}" ]] || [[ ! "${CUSTOM_PORT}" =~ ^[0-9]+$ ]] || [[ "${CUSTOM_PORT}" -lt 1 ]] || [[ "${CUSTOM_PORT}" -gt 65535 ]]; then
                warn "Invalid port; using 8443."
                HTTPS_PORT="8443"
            else
                HTTPS_PORT="${CUSTOM_PORT}"
                if [[ "${CUSTOM_PORT}" -lt 1024 ]]; then
                    warn "Ports below 1024 require setcap when not running as root."
                fi
                if _port_in_use "${HTTPS_PORT}"; then
                    echo ""
                    warn "Port ${HTTPS_PORT} is already in use."
                    _port_usage_info "${HTTPS_PORT}"
                    read -p "Use this port anyway? [y/N] " -n 1 -r
                    echo ""
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        info "Using port 8443 instead."
                        HTTPS_PORT="8443"
                    fi
                fi
            fi
            ;;
        *)
            warn "Unknown choice; using 8443."
            HTTPS_PORT="8443"
            ;;
    esac
    ok "HTTPS port set to: ${HTTPS_PORT}"
fi

# Write env file so systemd units can use it
mkdir -p "${DATA_DIR}"
ENV_FILE="${DATA_DIR}/ziochub.env"
echo "# ZIoCHub HTTPS port (generated by setup.sh)" > "${ENV_FILE}"
echo "ZIOCHUB_PORT=${HTTPS_PORT}" >> "${ENV_FILE}"
chown "${APP_USER}:${APP_GROUP}" "${ENV_FILE}"
chmod 640 "${ENV_FILE}"
ok "Port configuration written to ${ENV_FILE}"

# Allow binding to port 443 (or other <1024) as non-root: setcap on the venv Python
if [[ "${HTTPS_PORT}" =~ ^[0-9]+$ ]] && [[ "${HTTPS_PORT}" -lt 1024 ]]; then
    if command -v setcap &>/dev/null; then
        VENV_PYTHON="${VENV_DIR}/bin/python"
        [[ -x "${VENV_PYTHON}" ]] || VENV_PYTHON="${VENV_DIR}/bin/python3"
        if [[ -x "${VENV_PYTHON}" ]]; then
            if setcap 'cap_net_bind_service=+ep' "${VENV_PYTHON}" 2>/dev/null; then
                ok "Can bind to port ${HTTPS_PORT} (setcap cap_net_bind_service on python)"
            else
                warn "Could not set cap_net_bind_service on python. To use port ${HTTPS_PORT}, run as root or use a reverse proxy."
            fi
        else
            warn "venv python not found. To use port ${HTTPS_PORT}, run as root or use a reverse proxy."
        fi
    else
        warn "setcap not found. To use port ${HTTPS_PORT}, install libcap2-bin or use a reverse proxy."
    fi
fi

# ── 6. Systemd services ────────────────────────────────────────────────────
info "Installing systemd units..."

cp "${SCRIPT_DIR}/ziochub.service"          /etc/systemd/system/
cp "${SCRIPT_DIR}/ziochub-cleaner.service"  /etc/systemd/system/
cp "${SCRIPT_DIR}/ziochub-cleaner.timer"    /etc/systemd/system/
if [[ -f "${SCRIPT_DIR}/ziochub-backup.service" ]] && [[ -f "${SCRIPT_DIR}/ziochub-backup.timer" ]]; then
    cp "${SCRIPT_DIR}/ziochub-backup.service" /etc/systemd/system/
    cp "${SCRIPT_DIR}/ziochub-backup.timer"   /etc/systemd/system/
fi
if [[ -f "${SCRIPT_DIR}/ziochub-misp-sync.service" ]] && [[ -f "${SCRIPT_DIR}/ziochub-misp-sync.timer" ]]; then
    cp "${SCRIPT_DIR}/ziochub-misp-sync.service" /etc/systemd/system/
    cp "${SCRIPT_DIR}/ziochub-misp-sync.timer"   /etc/systemd/system/
fi

systemctl daemon-reload

systemctl enable ziochub.service
systemctl enable ziochub-cleaner.timer
if [[ -f "${SCRIPT_DIR}/ziochub-backup.timer" ]]; then
    systemctl enable ziochub-backup.timer
    systemctl start ziochub-backup.timer 2>/dev/null || true
fi
if [[ -f /etc/systemd/system/ziochub-misp-sync.timer ]]; then
    systemctl enable ziochub-misp-sync.timer
    systemctl start ziochub-misp-sync.timer 2>/dev/null || true
fi

systemctl restart ziochub.service
systemctl start   ziochub-cleaner.timer

ok "Systemd units installed & started."

# ── 7. Summary ──────────────────────────────────────────────────────────────
echo ""
if $UPGRADE; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         ZIoCHub — Upgrade Complete                     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         ZIoCHub — Installation Complete                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
fi
echo ""
info "Application path : ${APP_DIR}"
info "Data directory   : ${DATA_DIR}"
info "Service user     : ${APP_USER}"
echo ""
info "Paths:"
echo "    Application   : ${APP_DIR}"
echo "    Database      : ${DATA_DIR}/ziochub.db"
echo "    IOC files     : ${DATA_DIR}/Main/"
echo "    YARA rules    : ${DATA_DIR}/YARA/"
echo "    SSL certs     : ${DATA_DIR}/ssl/"
echo "    Backups       : ${DATA_DIR}/backups/"
[[ -d "${APP_DIR}/docs" ]] && echo "    Documentation : ${APP_DIR}/docs/"
echo ""

if $UPGRADE; then
    info "Your data was preserved:"
    echo "    - Database: ${DATA_DIR}/ziochub.db"
    echo "    - IOC files: ${DATA_DIR}/Main/"
    echo "    - YARA rules: ${DATA_DIR}/YARA/"
    echo "    - SSL certs: ${DATA_DIR}/ssl/"
    echo "    - Backups: ${DATA_DIR}/backups/"
    if ls "${DATA_DIR}"/allowlist.txt.bak.* &>/dev/null 2>&1; then
        echo ""
        info "Allowlist backup(s) created:"
        ls -1 "${DATA_DIR}"/allowlist.txt.bak.* 2>/dev/null | while read f; do echo "    - $f"; done
    fi
    echo ""
fi

systemctl --no-pager status ziochub.service || true

echo ""
SERVER_IP="$(hostname -I | awk '{print $1}')"
DISPLAY_PORT="${HTTPS_PORT:-8443}"
if [[ -f "${APP_DIR}/data/ssl/cert.pem" && -f "${APP_DIR}/data/ssl/key.pem" ]]; then
    info "Web UI available at: https://${SERVER_IP}:${DISPLAY_PORT}"
else
    info "Web UI available at: http://${SERVER_IP}:${DISPLAY_PORT}"
    info "Upload an SSL certificate via Admin > Certificate to enable HTTPS"
fi
echo ""
info "Useful commands:"
info "  journalctl -u ziochub -f               # Live logs"
info "  systemctl restart ziochub              # Restart app"
info "  systemctl status ziochub-cleaner.timer # Cleaner schedule"
info "  systemctl status ziochub-backup.timer  # Backup schedule"
info "  ./uninstall.sh --help                     # Uninstall options"
echo ""
