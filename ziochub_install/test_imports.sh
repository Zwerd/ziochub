#!/usr/bin/env bash
# ============================================================================
#  ZIoCHub — Import Verification Test
# ============================================================================
#  Tests Python imports after installation to verify all modules are available.
#
#  Usage:  ./test_imports.sh [venv_path]
#  Default: ./test_imports.sh /opt/ziochub/venv
# ============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

VENV_DIR="${1:-/opt/ziochub/venv}"

if [[ ! -d "$VENV_DIR" ]]; then
    fail "Virtual environment not found at: $VENV_DIR"
fi

if [[ ! -f "${VENV_DIR}/bin/python" ]]; then
    fail "Python interpreter not found in venv: ${VENV_DIR}/bin/python"
fi

PYTHON="${VENV_DIR}/bin/python"
APP_DIR="${VENV_DIR%/venv}"

# Change to app directory for imports
cd "$APP_DIR" || fail "Cannot change to app directory: $APP_DIR"

info "Testing Python imports from: $APP_DIR"
info "Using Python: $PYTHON"
echo ""

# Test core modules
REQUIRED_MODULES=("constants" "models" "extensions")
FAILED=()

for module in "${REQUIRED_MODULES[@]}"; do
    if "$PYTHON" -c "import ${module}" 2>/dev/null; then
        ok "Import successful: ${module}"
    else
        FAILED+=("${module}")
        fail "Import failed: ${module}"
    fi
done

# Test utils submodules
REQUIRED_UTILS=("validation" "refanger" "allowlist" "feed_helpers" "yara_utils" "validation_warnings")
FAILED_UTILS=()

for util in "${REQUIRED_UTILS[@]}"; do
    if "$PYTHON" -c "from utils.${util} import *" 2>/dev/null; then
        ok "Import successful: utils.${util}"
    else
        FAILED_UTILS+=("utils.${util}")
        fail "Import failed: utils.${util}"
    fi
done

# Test app.py can be imported (this tests all dependencies)
if "$PYTHON" -c "import app" 2>/dev/null; then
    ok "Import successful: app (main application)"
else
    fail "Import failed: app (main application)"
fi

echo ""
if [[ ${#FAILED[@]} -eq 0 ]] && [[ ${#FAILED_UTILS[@]} -eq 0 ]]; then
    ok "All Python imports verified successfully"
    exit 0
else
    fail "Some imports failed. Check errors above."
fi
