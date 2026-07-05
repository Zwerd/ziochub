#!/usr/bin/env bash
# ============================================================================
#  ZIoCHub — PostgreSQL .deb bundle for offline / air-gapped installs
# ============================================================================
#  Separate from package_offline.sh (application ZIP). Build on a machine with
#  the SAME distro + version as the target server (e.g. Ubuntu 22.04 → 22.04).
#
#  Usage:
#    sudo ./package_postgresql_debs.sh
#    ./package_postgresql_debs.sh --help
#
#  Output: ./ziochub_postgresql_debs_<os>_<arch>.zip
#
#  On target (lab / air-gap without IT-managed PostgreSQL):
#    mkdir -p ziochub_app ziochub_postgresql
#    unzip app ZIP → ziochub_app/   (contains setup.sh — the ONLY installer)
#    unzip PG ZIP → ziochub_postgresql/   (contains postgresql-debs/ only)
#    cd ziochub_app && sudo ./setup.sh --offline \
#      --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

show_help() {
    echo ""
    echo "Usage:  sudo ./package_postgresql_debs.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h    Show this help"
    echo ""
    echo "Builds a standalone ZIP with postgresql-debs/*.deb for offline PostgreSQL install."
    echo "NOT included in the main application installer (package_offline.sh)."
    echo ""
    echo "Production (IT-managed DB): skip this package; install PostgreSQL from your"
    echo "internal repo and run:  sudo ./setup.sh --offline --use-existing-postgresql"
    echo ""
    echo "Lab / air-gap: two SEPARATE directories on the target (one setup.sh only):"
    echo "  ziochub_app/        ← application ZIP"
    echo "  ziochub_postgresql/ ← this ZIP (postgresql-debs/ only)"
    echo "  cd ziochub_app && sudo ./setup.sh --offline \\"
    echo "    --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs"
    echo ""
    exit 0
}

for arg in "$@"; do
    [[ "$arg" == "--help" || "$arg" == "-h" ]] && show_help
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PG_SRC="${SCRIPT_DIR}/postgresql-debs"
DIST_DIR="${SCRIPT_DIR}/dist_pg_debs"

# OS slug for filename
OS_ID="linux"
OS_VERSION=""
ARCH="$(uname -m 2>/dev/null || echo unknown)"
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-linux}${VERSION_ID:+-${VERSION_ID}}"
fi
OS_SLUG=$(echo "${OS_ID}_${ARCH}" | tr ' ' '_' | tr -c 'A-Za-z0-9_.-' '_')
OUTPUT_ZIP="${SCRIPT_DIR}/ziochub_postgresql_debs_${OS_SLUG}.zip"

if [[ "${EUID}" -ne 0 ]]; then
    fail "Run as root: sudo ./package_postgresql_debs.sh"
fi

if [[ ! -f "${SCRIPT_DIR}/scripts/download_postgresql_debs.sh" ]]; then
    fail "Missing scripts/download_postgresql_debs.sh"
fi

info "Downloading PostgreSQL packages (postgresql + postgresql-client + ssl-cert + dependencies)..."
bash "${SCRIPT_DIR}/scripts/download_postgresql_debs.sh" "${PG_SRC}"

if [[ ! -f "${PG_SRC}/MANIFEST.txt" ]]; then
    warn "MANIFEST.txt missing — bundle may be from an older download script."
fi
if ! compgen -G "${PG_SRC}/ssl-cert_"*.deb >/dev/null 2>&1 \
    && ! compgen -G "${PG_SRC}/ssl-cert-"*.deb >/dev/null 2>&1; then
    fail "Bundle verification failed: ssl-cert .deb not found in ${PG_SRC}/" \
         "Re-run: sudo ./scripts/download_postgresql_debs.sh && sudo ./package_postgresql_debs.sh"
fi

DEB_COUNT=$(find "${PG_SRC}" -maxdepth 1 -type f -name '*.deb' 2>/dev/null | wc -l)
[[ "${DEB_COUNT}" -gt 0 ]] || fail "No .deb files in ${PG_SRC}/"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}/postgresql-debs"
find "${PG_SRC}" -maxdepth 1 -type f -name '*.deb' -exec cp -a {} "${DIST_DIR}/postgresql-debs/" \;
cp "${SCRIPT_DIR}/postgresql-debs/README.md" "${DIST_DIR}/postgresql-debs/" 2>/dev/null || true
cp "${PG_SRC}/MANIFEST.txt" "${DIST_DIR}/postgresql-debs/" 2>/dev/null || true

cat > "${DIST_DIR}/postgresql-debs/DEPLOY.txt" <<'EOF'
ZIoCHub — PostgreSQL offline package (NOT an installer)

This ZIP contains postgresql-debs/*.deb only. There is no setup.sh here.

On the target server (lab / air-gap):

  mkdir -p ziochub_app ziochub_postgresql
  python3 -m zipfile -e ziochub_*_installer.zip ziochub_app
  python3 -m zipfile -e ziochub_postgresql_debs_*.zip ziochub_postgresql
  cd ziochub_app && chmod +x *.sh
  sudo ./setup.sh --offline \
    --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs

Production: IT installs PostgreSQL; use only the app ZIP with
  sudo ./setup.sh --offline --use-existing-postgresql
EOF

info "Creating ${OUTPUT_ZIP} ..."
rm -f "${OUTPUT_ZIP}"
python3 -c "
import zipfile, os, sys, time
src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(src):
        for f in files:
            full = os.path.join(root, f)
            arc = os.path.relpath(full, src)
            st = os.stat(full)
            info = zipfile.ZipInfo(arc, date_time=time.localtime(st.st_mtime)[:6])
            with open(full, 'rb') as fh:
                zf.writestr(info, fh.read())
" "${DIST_DIR}" "${OUTPUT_ZIP}"

rm -rf "${DIST_DIR}"
SIZE=$(du -h "${OUTPUT_ZIP}" | awk '{print $1}')

echo ""
ok "PostgreSQL offline package ready"
info "File     : ${OUTPUT_ZIP}"
info "Size     : ${SIZE}"
info "Packages : ${DEB_COUNT} .deb file(s)"
info "Target OS: ${OS_ID} (${ARCH}) — build and install on matching distro/version"
echo ""
info "Lab / air-gap deploy (on TARGET — separate folders, ONE setup.sh):"
info "  mkdir -p ziochub_app ziochub_postgresql"
info "  python3 -m zipfile -e ziochub_*_installer.zip ziochub_app"
info "  python3 -m zipfile -e $(basename "${OUTPUT_ZIP}") ziochub_postgresql"
info "  cd ziochub_app && chmod +x *.sh"
info "  sudo ./setup.sh --offline --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs"
echo ""
info "Production: skip this ZIP; IT installs PostgreSQL on target, then:"
info "  sudo ./setup.sh --offline --use-existing-postgresql"
echo ""
info "See README: Lab / air-gap: PostgreSQL .deb via external Linux machine"
echo ""
