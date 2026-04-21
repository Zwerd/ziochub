#!/usr/bin/env bash
# Legacy name: use backup_ziochub.sh.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "${SCRIPT_DIR}/backup_ziochub.sh" "$@"
