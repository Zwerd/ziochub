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
#    ./setup.sh --check [--offline]   # Prerequisites only (no root; no install)
#    sudo ./setup.sh --help       # Full help with steps and paths
#
#  Installs to /opt/ziochub with data in /opt/ziochub/data/
#  Creates systemd services for the app, cleaner, backup, MISP.
#  Auto-generates a self-signed SSL certificate if openssl is available.
#  HTTPS port: 8443 (default), or 443 / custom. Port 443 requires setcap; see security note in installer.
#
#  Updated: 2026-04-13 — --check/--preflight; venv preflight uses real test create.
#  Offline domain sanity: utils/offline_domain_checks.py (import verified below).
#  GUI timestamps: utils/jinja_datetime.py (zoneinfo; host should have tzdata package on minimal Linux).
#  Updated: 2026-06 — post-upgrade feature checks (Admin Distribution, Feed Pulse, YARA_rejected, data/dxl).
#  Updated: 2026-06 — unified Inbox (utils/user_notifications.py, static/js/app.js, i18n).
#  Updated: 2026-06 — PostgreSQL-only fresh install; SQLite→PG migration on --upgrade.
# ============================================================================
set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Air-gap / offline: python3-venv install hints (no apt on target assumption) ─
# Prints one line per echo; consume with: done < <(ziochub_python3_venv_preflight_notes "$OFFLINE" "$PY_MM_FALLBACK")
# Arg2 is only used if python3 cannot report its version (fallback major.minor, e.g. 3.12).
ziochub_python3_venv_preflight_notes() {
    local want_offline="${1:-false}"
    local py_mm_fallback="${2:-3}"
    local pretty="unknown"
    local codename=""
    local os_id=""
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m 2>/dev/null || echo "amd64")
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        pretty="${PRETTY_NAME:-${NAME:-unknown}}"
        codename="${VERSION_CODENAME:-}"
        os_id="${ID:-}"
    fi

    local py_path
    py_path=$(command -v python3 2>/dev/null || true)
    local py_full="unknown"
    local py_dot="${py_mm_fallback}"
    if [[ -n "${py_path}" ]]; then
        py_full=$("${py_path}" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || echo "unknown")
        py_dot=$("${py_path}" -c 'import sys; print("%d.%d" % (sys.version_info.major, sys.version_info.minor))' 2>/dev/null || true)
    fi
    [[ -z "${py_dot}" ]] && py_dot="${py_mm_fallback}"
    # Debian/Ubuntu: version-tied package is python3.12-venv not python312-venv
    local ver_pkg="python${py_dot}-venv"

    local pkg_url_meta=""
    local pkg_url_ver=""
    if [[ "${os_id}" == "ubuntu" && -n "${codename}" ]]; then
        pkg_url_meta="https://packages.ubuntu.com/${codename}/python3-venv"
        pkg_url_ver="https://packages.ubuntu.com/${codename}/${ver_pkg}"
    elif [[ "${os_id}" == "debian" && -n "${codename}" ]]; then
        pkg_url_meta="https://packages.debian.org/${codename}/python3-venv"
        pkg_url_ver="https://packages.debian.org/${codename}/${ver_pkg}"
    else
        pkg_url_meta="https://packages.ubuntu.com/ or https://packages.debian.org/ (search: python3-venv; arch ${arch})"
        pkg_url_ver="(same site, search: ${ver_pkg})"
    fi

    echo "  Detected host: ${pretty}  (dpkg architecture: ${arch})."
    echo "  This machine python3: ${py_path:-python3}  →  Python ${py_full}"
    echo "  Debian/Ubuntu package names to install/download:"
    echo "       • python3-venv     — default choice (matches distro packaging for /usr/bin/python3)"
    echo "       • ${ver_pkg}  — tied to Python ${py_dot} on this host (use if you need an explicit venv for this version)"

    if [[ "${want_offline}" == "true" ]]; then
        echo "  --- Air-gapped (--offline): this server usually cannot use apt against the internet ---"
        echo "  A) On a PC with the SAME OS release and ${arch}, with network, run:"
        echo "       mkdir -p /tmp/ziochub_debs && cd /tmp/ziochub_debs"
        echo "       sudo apt-get update"
        echo "       sudo apt-get install --download-only -y -o Dir::Cache::archives=/tmp/ziochub_debs python3-venv"
        echo "     If python3-venv does not match Python ${py_full} on the target, also run:"
        echo "       sudo apt-get install --download-only -y -o Dir::Cache::archives=/tmp/ziochub_debs ${ver_pkg}"
        echo "     (Saves multiple .deb files into that folder — the requested package plus its dependencies, not a single file.)"
        echo "  B) Copy the entire folder (every .deb inside it) to this server."
        echo "  C) On this server:"
        echo "       cd /path/to/copied/debs && sudo dpkg -i *.deb"
        echo "     If dpkg reports missing packages, download those names on the online PC the same way."
        echo "  D) Manual .deb pages (${arch}, this OS release):"
        echo "       ${pkg_url_meta}"
        echo "       ${pkg_url_ver}"
    else
        echo "  On this server (with working apt + network):"
        echo "       sudo apt-get update && sudo apt-get install -y python3-venv"
        echo "  If that does not fix venv for Python ${py_full}:"
        echo "       sudo apt-get install -y ${ver_pkg}"
        echo "  Air-gapped later? Use the same steps as --offline (download .deb elsewhere):"
        echo "       ${pkg_url_meta}"
        echo "       ${pkg_url_ver}"
    fi
}

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
    echo "  --use-existing-postgresql"
    echo "                Do not install PostgreSQL packages. Expect a running local"
    echo "                cluster (production / IT-managed). setup.sh only creates"
    echo "                role, database, and data/ziochub.env."
    echo "                (Auto-detected when PostgreSQL is running or ziochub.env"
    echo "                already has PG credentials — flag is optional.)"
    echo "  --postgresql-debs-dir PATH"
    echo "                Offline lab: path to postgresql-debs/*.deb when extracted"
    echo "                outside the app directory (recommended: separate folders)."
    echo "  --upgrade     Upgrade an existing installation. Preserves database,"
    echo "                IOC files, YARA rules, SSL certificates, and allowlist.txt."
    echo "  --check, --preflight"
    echo "                Verify host prerequisites only (Python venv, systemd, files,"
    echo "                offline packages if --offline). Does not require root; makes"
    echo "                no changes. Example: ./setup.sh --check --offline"
    echo "  --help, -h    Show this help message and exit."
    echo ""
    echo "Modes:"
    echo "  Fresh install (online)    sudo ./setup.sh"
    echo "  Fresh install (offline)   sudo ./setup.sh --offline"
    echo "  Production upgrade        sudo ./setup.sh --offline --upgrade"
    echo "                            (auto-detects PostgreSQL when running or in ziochub.env)"
    echo "  Upgrade (online)          sudo ./setup.sh --upgrade"
    echo "  Upgrade (offline)         sudo ./setup.sh --offline --upgrade"
    echo ""
    echo "PostgreSQL (read before install):"
    echo "  • There is ONE setup.sh (application ZIP only). PostgreSQL ZIP has .deb files only."
    echo "  • Recommended layout on target:"
    echo "      ziochub_app/          ← application ZIP"
    echo "      ziochub_postgresql/   ← PostgreSQL ZIP (contains postgresql-debs/)"
    echo "    cd ziochub_app && sudo ./setup.sh --offline \\"
    echo "      --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs"
    echo "  • Production: IT installs PostgreSQL; setup auto-detects it on upgrade."
    echo "    Explicit flag still works: --use-existing-postgresql"
    echo ""
    echo "What the installer does:"
    echo "  1. Runs pre-flight checks (Python, systemd, openssl, required files)"
    echo "  2. Creates system user 'ziochub'"
    echo "  3. Copies application files to /opt/ziochub"
    echo "  4. Creates Python venv and installs dependencies"
    echo "  5. Provisions PostgreSQL and initializes the application schema"
    echo "  6. Generates a self-signed SSL certificate (requires openssl)"
    echo "  7. Asks which HTTPS port to use (8443 default, or 443 with security note)"
    echo "  8. Installs and enables systemd services:"
    echo "       - ziochub.service"
    echo "       - ziochub-cleaner.service, ziochub-cleaner.timer"
    echo "       - ziochub-backup.service, ziochub-backup.timer"
    echo "       - ziochub-misp-sync.service, ziochub-misp-sync.timer"
    echo "       - ziochub-taxii-sync.service, ziochub-taxii-sync.timer"
    echo ""
    echo "HTTPS port:"
    echo "  Default is 8443. You can choose 443 (requires setcap; see security note in installer)"
    echo "  or a custom port. Port is stored in /opt/ziochub/data/ziochub.env (ZIOCHUB_PORT)."
    echo ""
    echo "Paths:"
    echo "  Application   /opt/ziochub"
    echo "  Database      PostgreSQL (local); credentials in /opt/ziochub/data/ziochub.env"
    echo "  Legacy SQLite /opt/ziochub/data/ziochub.db (upgrade migration only; archived after migrate)"
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
CHECK_ONLY=false
USE_EXISTING_PG=false
USE_EXISTING_PG_AUTO=false
POSTGRESQL_DEBS_DIR=""
_expect_pg_debs_dir=false
for arg in "$@"; do
    if $_expect_pg_debs_dir; then
        POSTGRESQL_DEBS_DIR="$arg"
        _expect_pg_debs_dir=false
        continue
    fi
    [[ "$arg" == "--help" || "$arg" == "-h" ]] && show_help
    [[ "$arg" == "--offline" ]] && OFFLINE=true
    [[ "$arg" == "--upgrade" ]] && UPGRADE=true
    [[ "$arg" == "--check" || "$arg" == "--preflight" ]] && CHECK_ONLY=true
    [[ "$arg" == "--use-existing-postgresql" ]] && USE_EXISTING_PG=true
    [[ "$arg" == "--postgresql-debs-dir" ]] && _expect_pg_debs_dir=true
    [[ "$arg" == --postgresql-debs-dir=* ]] && POSTGRESQL_DEBS_DIR="${arg#--postgresql-debs-dir=}"
done
[[ "$_expect_pg_debs_dir" == true ]] && fail "--postgresql-debs-dir requires a path argument"

# ── Constants (needed before --check and before root check) ─────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_USER="ziochub"
APP_GROUP="ziochub"
APP_DIR="/opt/ziochub"
DATA_DIR="${APP_DIR}/data"
VENV_DIR="${APP_DIR}/venv"
ENV_FILE="${DATA_DIR}/ziochub.env"

# Legacy SQLite pending migration: do not let "import app" seed PostgreSQL during setup
if [[ -f "${DATA_DIR}/ziochub.db" ]]; then
    export ZIOCHUB_SKIP_DB_INIT=1
fi

# PostgreSQL provisioning helpers (also used by backup_ziochub.sh patterns)
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/scripts/postgres_install.sh" 2>/dev/null || {
    fail "Missing scripts/postgres_install.sh — rebuild the installer package."
}
if [[ -n "${POSTGRESQL_DEBS_DIR}" ]]; then
    POSTGRESQL_DEBS_DIR="$(cd "${POSTGRESQL_DEBS_DIR}" 2>/dev/null && pwd || true)"
    [[ -z "${POSTGRESQL_DEBS_DIR}" ]] && fail "Invalid --postgresql-debs-dir path"
    export ZIOCHUB_POSTGRESQL_DEBS_DIR="${POSTGRESQL_DEBS_DIR}"
fi

# Auto-detect existing PostgreSQL: production/IT cluster or install already migrated to PG.
# Makes `sudo ./setup.sh --offline --upgrade` behave like --use-existing-postgresql when appropriate.
if ! $USE_EXISTING_PG && ziochub_detect_use_existing_postgresql "${ENV_FILE}"; then
    USE_EXISTING_PG=true
    USE_EXISTING_PG_AUTO=true
fi

if ! $CHECK_ONLY; then
    [[ $EUID -ne 0 ]] && fail "This script must be run as root (sudo ./setup.sh)"
fi

# ── Fix permissions (ZIP extraction may strip +x from .sh files) ───────────
chmod +x "${SCRIPT_DIR}/"*.sh 2>/dev/null || true
chmod +x "${SCRIPT_DIR}/scripts/"*.sh 2>/dev/null || true

# ── Must NOT run from installed dir (upgrade would copy old over old) ───────
if ! $CHECK_ONLY; then
    SCRIPT_CANON=$(readlink -f "${SCRIPT_DIR}" 2>/dev/null || realpath "${SCRIPT_DIR}" 2>/dev/null || echo "${SCRIPT_DIR}")
    APP_CANON=$(readlink -f "${APP_DIR}" 2>/dev/null || realpath "${APP_DIR}" 2>/dev/null || echo "${APP_DIR}")
    if [[ "${SCRIPT_CANON}" == "${APP_CANON}" ]] || [[ "${SCRIPT_DIR}" == "${APP_DIR}" ]]; then
        fail "Do not run setup.sh from the installed directory (${APP_DIR})." \
             "Extract the installer ZIP to a separate folder (e.g. ziochub_install), then run: cd ziochub_install && sudo ./setup.sh --upgrade --offline"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
#  PRE-FLIGHT CHECKS — Verify all requirements before starting installation
# ════════════════════════════════════════════════════════════════════════════
echo ""
if $CHECK_ONLY; then
    info "Running prerequisite check only (--check / --preflight). No installation will be performed."
else
    info "Running pre-flight checks..."
fi
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

# Check Python venv: must be able to create a real environment (stricter than --help)
if command -v python3 &>/dev/null; then
    TEST_VENV_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ziochub_venv_test.XXXXXX" 2>/dev/null || true)
    if [[ -n "${TEST_VENV_DIR}" ]] && [[ -d "${TEST_VENV_DIR}" ]]; then
        if python3 -m venv "${TEST_VENV_DIR}" 2>/dev/null; then
            rm -rf "${TEST_VENV_DIR}"
            ok "Python venv: test environment created successfully"
        else
            rm -rf "${TEST_VENV_DIR}" 2>/dev/null || true
            PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3")
            
            # Online mode: try to install python3-venv automatically
            if ! $OFFLINE && ! $CHECK_ONLY; then
                warn "python3-venv not available. Attempting automatic installation..."
                VENV_INSTALLED=false
                
                # Detect package manager and install
                if command -v apt-get &>/dev/null; then
                    info "Detected apt package manager. Installing python3-venv..."
                    if apt-get update -qq 2>/dev/null && apt-get install -y python3-venv 2>/dev/null; then
                        VENV_INSTALLED=true
                    else
                        # Try version-specific package (e.g., python3.12-venv)
                        info "Trying version-specific package: python${PY_VER}-venv..."
                        apt-get install -y "python${PY_VER}-venv" 2>/dev/null && VENV_INSTALLED=true
                    fi
                elif command -v dnf &>/dev/null; then
                    info "Detected dnf package manager. Installing python3-venv..."
                    dnf install -y python3-venv 2>/dev/null && VENV_INSTALLED=true
                elif command -v yum &>/dev/null; then
                    info "Detected yum package manager. Installing python3-venv..."
                    yum install -y python3-venv 2>/dev/null && VENV_INSTALLED=true
                fi
                
                # Verify installation worked
                if $VENV_INSTALLED; then
                    TEST_VENV_DIR2=$(mktemp -d "${TMPDIR:-/tmp}/ziochub_venv_test2.XXXXXX" 2>/dev/null || true)
                    if [[ -n "${TEST_VENV_DIR2}" ]] && python3 -m venv "${TEST_VENV_DIR2}" 2>/dev/null; then
                        rm -rf "${TEST_VENV_DIR2}"
                        ok "python3-venv installed and verified successfully"
                    else
                        rm -rf "${TEST_VENV_DIR2}" 2>/dev/null || true
                        PREFLIGHT_ERRORS+=("python3-venv was installed but venv creation still fails.")
                        while IFS= read -r _venv_line || [[ -n "${_venv_line}" ]]; do
                            [[ -z "${_venv_line}" ]] && continue
                            PREFLIGHT_ERRORS+=("${_venv_line}")
                        done < <(ziochub_python3_venv_preflight_notes "$OFFLINE" "${PY_VER}")
                    fi
                else
                    PREFLIGHT_ERRORS+=("Failed to install python3-venv automatically.")
                    PREFLIGHT_ERRORS+=("Please install it manually: sudo apt-get install python3-venv")
                    while IFS= read -r _venv_line || [[ -n "${_venv_line}" ]]; do
                        [[ -z "${_venv_line}" ]] && continue
                        PREFLIGHT_ERRORS+=("${_venv_line}")
                    done < <(ziochub_python3_venv_preflight_notes "$OFFLINE" "${PY_VER}")
                fi
            else
                # Offline or check-only mode: cannot auto-install, show instructions
                PREFLIGHT_ERRORS+=("Cannot create a Python virtual environment (python3 -m venv failed).")
                while IFS= read -r _venv_line || [[ -n "${_venv_line}" ]]; do
                    [[ -z "${_venv_line}" ]] && continue
                    PREFLIGHT_ERRORS+=("${_venv_line}")
                done < <(ziochub_python3_venv_preflight_notes "$OFFLINE" "${PY_VER}")
            fi
        fi
    else
        PREFLIGHT_ERRORS+=("Could not create a temporary directory to test python3 -m venv.")
    fi
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
    "taxii_pull_settings.py"
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

# PostgreSQL scripts (required for install)
if [[ -f "${SCRIPT_DIR}/scripts/postgres_install.sh" ]] && [[ -f "${SCRIPT_DIR}/scripts/migrate_sqlite_to_postgres.py" ]]; then
    ok "PostgreSQL install/migration scripts found"
else
    PREFLIGHT_ERRORS+=("Missing scripts/postgres_install.sh or scripts/migrate_sqlite_to_postgres.py")
fi

if pg_isready -h 127.0.0.1 -q 2>/dev/null || command -v psql &>/dev/null; then
    ok "PostgreSQL detected (running or client tools present)"
    if $USE_EXISTING_PG_AUTO; then
        ok "Using existing PostgreSQL (--use-existing-postgresql auto-detected)"
    fi
elif $USE_EXISTING_PG; then
    PREFLIGHT_ERRORS+=("PostgreSQL not reachable — install and start PostgreSQL before setup, or omit --use-existing-postgresql and provide postgresql-debs/ from package_postgresql_debs.sh")
elif $OFFLINE; then
    _pg_debs_check="$(ziochub_postgresql_debs_dir 2>/dev/null || echo "${SCRIPT_DIR}/postgresql-debs")"
    if [[ -d "${_pg_debs_check}" ]] && ls "${_pg_debs_check}/"*.deb &>/dev/null 2>&1; then
        ok "PostgreSQL .deb packages found: ${_pg_debs_check}"
    else
        PREFLIGHT_WARNINGS+=("PostgreSQL .deb not found. Production: IT + --use-existing-postgresql. Lab: extract PostgreSQL ZIP to ziochub_postgresql/ and use --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs")
    fi
fi
unset _pg_debs_check

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

if $CHECK_ONLY; then
    ok "Prerequisite check complete. No changes were made."
    info "Next: install any missing packages above, then run: sudo ./setup.sh [--offline] [--upgrade]"
    exit 0
fi

# ── Detect existing installation ────────────────────────────────────────────
EXISTING_INSTALL=false
if [[ -d "${APP_DIR}" ]] && [[ -f "${APP_DIR}/app.py" ]]; then
    EXISTING_INSTALL=true
fi

if $EXISTING_INSTALL && ! $UPGRADE; then
    _upgrade_cmd="sudo ./setup.sh --upgrade"
    $OFFLINE && _upgrade_cmd="sudo ./setup.sh --offline --upgrade"
    if [[ -f "${DATA_DIR}/ziochub.db" ]]; then
        fail "Existing ZIoCHub installation detected at ${APP_DIR} (legacy SQLite: ${DATA_DIR}/ziochub.db)." \
             "You must re-run with --upgrade to update and migrate to PostgreSQL:" \
             "  ${_upgrade_cmd}" \
             "PostgreSQL is auto-detected when running; offline lab may need --postgresql-debs-dir." \
             "To remove the old install first: sudo ./uninstall.sh --backup"
    else
        fail "Existing ZIoCHub installation detected at ${APP_DIR}." \
             "You must re-run with --upgrade (do not run a fresh install over an existing one):" \
             "  ${_upgrade_cmd}" \
             "To remove the old install first: sudo ./uninstall.sh --backup"
    fi
fi

# ── Banner ──────────────────────────────────────────────────────────────────
echo ""
if $UPGRADE; then
    info "ZIoCHub Production Installer (UPGRADE MODE)"
    if $USE_EXISTING_PG_AUTO; then
        info "PostgreSQL: existing cluster (auto-detected)"
    elif $USE_EXISTING_PG; then
        info "PostgreSQL: existing cluster (--use-existing-postgresql)"
    fi
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
    systemctl stop ziochub-taxii-sync.timer 2>/dev/null || true
    systemctl stop ziochub-taxii-sync.service 2>/dev/null || true
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
mkdir -p "${APP_DIR}" "${DATA_DIR}" "${DATA_DIR}/Main" "${DATA_DIR}/YARA" "${DATA_DIR}/YARA_pending" "${DATA_DIR}/YARA_rejected" "${DATA_DIR}/dxl" "${DATA_DIR}/backups"
ok "Directories ready: ${APP_DIR}"

# ── 3. Copy application files (overwrites existing on upgrade) ─────────────
info "Copying application files..."

cp "${SCRIPT_DIR}/app.py"           "${APP_DIR}/"
cp "${SCRIPT_DIR}/cleaner.py"       "${APP_DIR}/"
cp "${SCRIPT_DIR}/start.sh"         "${APP_DIR}/"
chmod +x "${APP_DIR}/start.sh"
[[ -f "${SCRIPT_DIR}/misp_sync_job.py" ]] && cp "${SCRIPT_DIR}/misp_sync_job.py" "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/misp_settings.py" ]] && cp "${SCRIPT_DIR}/misp_settings.py" "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/taxii_sync_job.py" ]] && cp "${SCRIPT_DIR}/taxii_sync_job.py" "${APP_DIR}/"
[[ -f "${SCRIPT_DIR}/taxii_pull_settings.py" ]] && cp "${SCRIPT_DIR}/taxii_pull_settings.py" "${APP_DIR}/"
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

# Allowlist: seed from package on first install only — never overwrite ${DATA_DIR}/allowlist.txt
# on upgrade (Admin panel edits and offline server config must survive ./setup.sh --upgrade).
if [[ -f "${SCRIPT_DIR}/data/allowlist.txt" ]]; then
    if [[ -f "${DATA_DIR}/allowlist.txt" ]]; then
        ok "Allowlist already present — left unchanged (upgrade-safe)."
    else
        cp "${SCRIPT_DIR}/data/allowlist.txt" "${DATA_DIR}/"
        ok "Allowlist seeded from package (first install)."
    fi
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

# ── 3b. Verify recent feature files landed (catch stale offline ZIP) ───────
_verify_installed_file() {
    local rel="$1"
    local label="$2"
    if [[ ! -f "${APP_DIR}/${rel}" ]]; then
        warn "Missing after copy: ${rel} — ${label} may be unavailable."
        return 1
    fi
    return 0
}

FEATURE_CHECK_FAILED=false
_verify_installed_file "templates/admin/downstream.html" "Admin → Distribution" || FEATURE_CHECK_FAILED=true
_verify_installed_file "templates/admin/base.html" "Admin navigation" || FEATURE_CHECK_FAILED=true
_verify_installed_file "utils/downstream.py" "Distribution / vendor icons" || FEATURE_CHECK_FAILED=true
_verify_installed_file "static/js/feed-pulse.js" "Feed Pulse (Connections / Push / Pull state)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "utils/user_notifications.py" "Unified Inbox (YARA/tag approval notifications)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "utils/audit_events.py" "CEF audit catalog and helpers" || FEATURE_CHECK_FAILED=true
_verify_installed_file "templates/admin/logs.html" "Admin → Logs (CEF audit filters)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "static/js/app.js" "Main SPA (unified Inbox bell UI)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "static/js/submit.js" "Submit IOC (tag suggest in single/bulk staging)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "static/js/search.js" "Search & Investigate (tag suggest on IOC edit)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "static/js/live-stats.js" "Live Feed (guest username privacy)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "templates/admin/settings.html" "Admin → Settings (Tags governance UI)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "utils/tags.py" "Tags governance (allowed list, suggest workflow)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "static/i18n/en.json" "Inbox + tags i18n (English)" || FEATURE_CHECK_FAILED=true
_verify_installed_file "static/i18n/he.json" "Inbox + tags i18n (Hebrew)" || FEATURE_CHECK_FAILED=true
if $FEATURE_CHECK_FAILED; then
    echo ""
    warn "Some newer UI modules are missing under ${APP_DIR}."
    warn "This usually means the installer ZIP was built from an older source tree."
    warn "Fix: on a dev machine with the latest repo, run ./package_offline.sh, transfer the new ZIP,"
    warn "     extract to a folder outside ${APP_DIR}, then: sudo ./setup.sh --offline --upgrade"
    echo ""
fi

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
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "3")
    echo ""
    echo -e "${RED}[FAIL]${NC} Failed to create virtual environment (python3 -m venv)."
    while IFS= read -r _venv_line || [[ -n "${_venv_line}" ]]; do
        [[ -z "${_venv_line}" ]] && continue
        echo "  ${_venv_line}"
    done < <(ziochub_python3_venv_preflight_notes "$OFFLINE" "${PY_VER}")
    echo ""
    echo -e "${CYAN}[INFO]${NC}  After installing python3-venv (or equivalent), run this installer again."
    exit 1
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

# YARA syntax validation in the UI requires yara-python import.
if "${VENV_DIR}/bin/python" -c "import yara" 2>/dev/null; then
    ok "yara-python import check passed (YARA syntax validation enabled)."
else
    warn "yara-python import check failed."
    warn "YARA Manager -> Write -> Check syntax may fail until yara-python is installed."
fi

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
REQUIRED_UTILS=("validation" "refanger" "allowlist" "feed_helpers" "yara_utils" "offline_domain_checks" "validation_warnings" "validation_messages" "sanity_checks" "auth" "decorators" "ldap_auth" "champs" "ioc_decode" "upload_text_encoding" "misp_sync" "cef_logger" "audit_events" "mentorship" "ambition" "jinja_datetime" "downstream" "integration_telemetry" "user_notifications" "tags" "db_config" "schema_migrations")
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

# Trellix Email Security (EX) + NX wmps session YARA: each module checked separately with full stderr for diagnosis.
info "Verifying Trellix YARA integration modules (utils.trellix_ex, utils.trellix_nx)..."
TRELLIX_UTILS_IMPORT_FAILED=false
for _trellix_util in trellix_ex trellix_nx; do
    if _trellix_err=$(
        cd "${APP_DIR}" && "${VENV_DIR}/bin/python" -c "
import sys
import traceback
try:
    __import__('utils.${_trellix_util}')
except Exception:
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
" 2>&1
    ); then
        ok "utils.${_trellix_util} - import OK"
    else
        TRELLIX_UTILS_IMPORT_FAILED=true
        warn "utils.${_trellix_util} - import FAILED. Admin -> Integrations (Trellix EX / NX YARA) may be broken until this is fixed."
        while IFS= read -r _tl || [[ -n "${_tl}" ]]; do
            echo -e "    ${YELLOW}│${NC}  ${_tl}"
        done <<< "${_trellix_err}"
    fi
done
if $TRELLIX_UTILS_IMPORT_FAILED; then
    warn "Diagnosis: if you see ImportError/ModuleNotFoundError for a third-party package, refresh offline wheels (pip download -d packages/ -r requirements.txt ...) and rebuild the installer."
    warn "If trellix_nx fails after trellix_ex succeeded, the traceback below trellix_nx is specific to NX wmps wiring."
fi

# Configurable GUI timezone (Admin → Settings → gui_display_timezone)
if "${VENV_DIR}/bin/python" -c "from utils.jinja_datetime import get_gui_display_timezone; get_gui_display_timezone()" 2>/dev/null; then
    ok "utils.jinja_datetime - import OK (display timezone: $("${VENV_DIR}/bin/python" -c "from utils.jinja_datetime import get_gui_display_timezone; print(get_gui_display_timezone())" 2>/dev/null || echo '?'))"
else
    warn "utils.jinja_datetime import failed — timestamp display may break. Ensure tzdata is installed (apt install tzdata)."
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

# ── 5c. PostgreSQL + application database ───────────────────────────────────
# (Schema init runs after ziochub.env is written — see section 5e below)

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

# Write env file (HTTPS port + PostgreSQL credentials) for systemd / app
mkdir -p "${DATA_DIR}"
ziochub_install_postgresql_packages "$OFFLINE" "$USE_EXISTING_PG"
ziochub_ensure_postgresql_service

ziochub_read_pg_password_from_env_file "${ENV_FILE}"
if [[ -z "${ZIOCHUB_PG_PASSWORD:-}" ]]; then
    ZIOCHUB_PG_PASSWORD="$(ziochub_pg_generate_password)"
fi
ziochub_create_postgresql_role_and_db "${ZIOCHUB_PG_PASSWORD}"
ziochub_write_database_env "${ENV_FILE}" "${HTTPS_PORT}" "${ZIOCHUB_PG_PASSWORD}"
ok "Database configuration written to ${ENV_FILE}"

if [[ -f "${DATA_DIR}/ziochub.db" ]]; then
    ziochub_run_sqlite_migration_if_needed "${APP_DIR}" "${VENV_DIR}"
else
    unset ZIOCHUB_SKIP_DB_INIT
    ziochub_init_application_database "${APP_DIR}" "${VENV_DIR}"
    if $UPGRADE && [[ -f "${DATA_DIR}/ziochub.env" ]]; then
        ziochub_postgresql_health_check "${APP_DIR}" "${VENV_DIR}"
    fi
fi
unset ZIOCHUB_SKIP_DB_INIT

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
if [[ -f "${SCRIPT_DIR}/ziochub-taxii-sync.service" ]] && [[ -f "${SCRIPT_DIR}/ziochub-taxii-sync.timer" ]]; then
    cp "${SCRIPT_DIR}/ziochub-taxii-sync.service" /etc/systemd/system/
    cp "${SCRIPT_DIR}/ziochub-taxii-sync.timer"   /etc/systemd/system/
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
if [[ -f /etc/systemd/system/ziochub-taxii-sync.timer ]]; then
    systemctl enable ziochub-taxii-sync.timer
    systemctl start ziochub-taxii-sync.timer 2>/dev/null || true
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
echo "    Database      : PostgreSQL ${ZIOCHUB_PG_DB} @ ${ZIOCHUB_PG_HOST}:${ZIOCHUB_PG_PORT}"
echo "    DB config     : ${ENV_FILE}"
echo "    IOC files     : ${DATA_DIR}/Main/"
echo "    YARA rules    : ${DATA_DIR}/YARA/"
echo "    SSL certs     : ${DATA_DIR}/ssl/"
echo "    Backups       : ${DATA_DIR}/backups/"
[[ -d "${APP_DIR}/docs" ]] && echo "    Documentation : ${APP_DIR}/docs/"
echo ""

INSTALLED_VERSION=""
if [[ -f "${APP_DIR}/constants.py" ]]; then
    INSTALLED_VERSION=$(grep -E '^VERSION\s*=' "${APP_DIR}/constants.py" 2>/dev/null | sed -E "s/.*[\"']([^\"']+)[\"'].*/\1/" | tr -d '\r' || true)
fi
if [[ -n "${INSTALLED_VERSION}" ]]; then
    info "Installed application version: ${INSTALLED_VERSION}"
fi

if $UPGRADE; then
    info "Your data was preserved:"
    echo "    - Database: PostgreSQL (${ZIOCHUB_PG_DB})"
    if [[ -f "${DATA_DIR}/ziochub.db" ]]; then
        echo "    - Legacy SQLite pending migration: ${DATA_DIR}/ziochub.db"
    fi
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
