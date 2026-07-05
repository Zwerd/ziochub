#!/usr/bin/env bash
# ============================================================================
#  ZIoCHub — Download PostgreSQL .deb packages for offline install
# ============================================================================
#  Run on a Debian/Ubuntu machine WITH internet. Target server must use the
#  SAME distro + major version (e.g. Ubuntu 22.04 → Ubuntu 22.04).
#
#  Downloads postgresql + postgresql-client AND all recursive dependencies,
#  including ssl-cert (required to configure postgresql-14 on a clean host).
#
#  Usage (from project root):
#    sudo ./scripts/download_postgresql_debs.sh
#    sudo ./scripts/download_postgresql_debs.sh /path/to/postgresql-debs
#
#  Then: sudo ./package_postgresql_debs.sh
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEST="${1:-${PROJECT_ROOT}/postgresql-debs}"

# Root packages to pull. ssl-cert is explicit — apt --download-only on a machine
# that already has ssl-cert installed often omits it from the cache.
ROOT_PKGS=(postgresql postgresql-client ssl-cert)

# Must exist as .deb in the bundle (basename prefix before _version).
CRITICAL_DEB_PREFIXES=(
    ssl-cert
    postgresql-common
    postgresql-client-common
    postgresql-client
    postgresql
    libpq5
)

if [[ "${EUID}" -ne 0 ]]; then
    fail "Run as root (sudo) so apt can resolve and download all dependencies." \
         "Example: sudo ${SCRIPT_DIR}/download_postgresql_debs.sh"
fi

if ! command -v apt-get &>/dev/null; then
    fail "This script requires apt-get (Debian/Ubuntu). Build the offline package on a matching distro."
fi

# Return 0 if dest/ contains a .deb for package name prefix (e.g. ssl-cert).
_deb_present() {
    local dest="$1"
    local prefix="$2"
    compgen -G "${dest}/${prefix}_"*.deb >/dev/null 2>&1 && return 0
    compgen -G "${dest}/${prefix}-"*.deb >/dev/null 2>&1 && return 0
    compgen -G "${dest}/${prefix}[0-9]"*.deb >/dev/null 2>&1 && return 0
    return 1
}

# Breadth-first collect Depends/PreDepends (no Recommends/Suggests).
_collect_dep_closure() {
    local pkg dep
    local -A seen=()
    local queue=("$@")
    local result=()

    while ((${#queue[@]})); do
        pkg="${queue[0]}"
        queue=("${queue[@]:1}")
        [[ -z "${pkg}" ]] && continue
        [[ -n "${seen[$pkg]+x}" ]] && continue
        seen["$pkg"]=1
        result+=("$pkg")
        while IFS= read -r dep; do
            [[ -z "${dep}" ]] && continue
            [[ "${dep}" == *"|"* ]] && continue
            [[ "${dep}" == "<"* ]] && continue
            queue+=("${dep}")
        done < <(
            apt-cache depends --no-recommends --no-suggests --no-conflicts \
                --no-breaks --no-replaces --no-enhances "${pkg}" 2>/dev/null \
                | awk '/^(Pre)?Depends:/ { for (i=2; i<=NF; i++) if ($i !~ /^</) print $i }'
        )
    done
    printf '%s\n' "${result[@]}" | sort -u
}

_download_pkg() {
    local dest="$1"
    local pkg="$2"
    if _deb_present "${dest}" "${pkg}"; then
        return 0
    fi
    (cd "${dest}" && DEBIAN_FRONTEND=noninteractive apt-get download "${pkg}" 2>/dev/null) \
        || warn "Could not download: ${pkg}"
}

_verify_bundle() {
    local dest="$1"
    local missing=()
    local prefix

    for prefix in "${CRITICAL_DEB_PREFIXES[@]}"; do
        _deb_present "${dest}" "${prefix}" || missing+=("${prefix}")
    done

    if ! compgen -G "${dest}/postgresql-[0-9]*_*.deb" >/dev/null \
        && ! compgen -G "${dest}/postgresql-[0-9]*-*.deb" >/dev/null; then
        missing+=("postgresql-<version> (e.g. postgresql-14)")
    fi

    if ((${#missing[@]})); then
        echo ""
        fail "Bundle incomplete — missing .deb for: ${missing[*]}" \
             "" \
             "Rebuild on Ubuntu/Debian matching the target, with working apt sources:" \
             "  sudo ./scripts/download_postgresql_debs.sh" \
             "  sudo ./package_postgresql_debs.sh"
    fi

    # sysstat (optional in closure) needs libsensors5 — warn if sysstat present without sensors
    if _deb_present "${dest}" sysstat && ! _deb_present "${dest}" libsensors5; then
        warn "sysstat .deb is bundled but libsensors5 is missing — downloading libsensors5..."
        _download_pkg "${dest}" libsensors5
        _download_pkg "${dest}" libsensors-config
    fi
}

_write_manifest() {
    local dest="$1"
    local manifest="${dest}/MANIFEST.txt"
    {
        echo "# ZIoCHub PostgreSQL offline bundle"
        echo "# Built: $(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
        echo "# Host: $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
        echo "# Packages:"
        find "${dest}" -maxdepth 1 -type f -name '*.deb' -printf '%f\n' 2>/dev/null \
            | sort
    } > "${manifest}"
}

mkdir -p "${DEST}/partial"
export DEBIAN_FRONTEND=noninteractive

info "Destination: ${DEST}"
info "Host: $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"

apt-get update -qq || warn "apt-get update had warnings (continuing)."

rm -rf "${DEST}/partial"/*
mkdir -p "${DEST}/partial"

info "Phase 1: apt-get --download-only (postgresql + postgresql-client + ssl-cert)..."
if ! apt-get install -y --download-only --reinstall \
    -o Dir::Cache::archives="${DEST}" \
    -o Dir::Cache::archives::partial="${DEST}/partial" \
    postgresql postgresql-client ssl-cert 2>/dev/null; then
    if ! apt-get install -y --download-only \
        -o Dir::Cache::archives="${DEST}" \
        -o Dir::Cache::archives::partial="${DEST}/partial" \
        postgresql postgresql-client ssl-cert; then
        fail "apt-get download failed. Ensure postgresql packages exist for this distro/release."
    fi
fi

info "Phase 2: recursive dependency closure (apt-get download any missing)..."
mapfile -t ALL_PKGS < <(_collect_dep_closure "${ROOT_PKGS[@]}")
info "Resolved ${#ALL_PKGS[@]} package(s) in dependency closure."
for pkg in "${ALL_PKGS[@]}"; do
    _download_pkg "${DEST}" "${pkg}"
done

# Explicit extras seen missing on clean air-gap targets
for extra in ssl-cert libsensors5 libsensors-config; do
    _download_pkg "${DEST}" "${extra}"
done

DEB_COUNT=$(find "${DEST}" -maxdepth 1 -type f -name '*.deb' 2>/dev/null | wc -l)
if [[ "${DEB_COUNT}" -eq 0 ]]; then
    fail "No .deb files in ${DEST}. Check apt sources and try: apt-cache policy postgresql"
fi

info "Phase 3: verify critical packages..."
_verify_bundle "${DEST}"

_write_manifest "${DEST}"

ok "Downloaded ${DEB_COUNT} .deb file(s) to ${DEST}/"
info "Manifest: ${DEST}/MANIFEST.txt"
info "Create standalone ZIP: sudo ./package_postgresql_debs.sh"
info "Production (IT-managed PG): skip this ZIP; use setup.sh --offline --use-existing-postgresql"
