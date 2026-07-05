#!/usr/bin/env bash
# ============================================================================
#  ZIoCHub — PostgreSQL provisioning (sourced by setup.sh)
# ============================================================================
#  Fresh installs: local PostgreSQL role + database + ziochub.env credentials.
#  Upgrade: if legacy ziochub.db exists, run scripts/migrate_sqlite_to_postgres.py
# ============================================================================

ZIOCHUB_PG_DB="${ZIOCHUB_PG_DB:-ziochub}"
ZIOCHUB_PG_USER="${ZIOCHUB_PG_USER:-ziochub}"
ZIOCHUB_PG_HOST="${ZIOCHUB_PG_HOST:-127.0.0.1}"
ZIOCHUB_PG_PORT="${ZIOCHUB_PG_PORT:-5432}"

# Directory with *.deb for offline install. Default: postgresql-debs/ next to setup.sh.
# Override: setup.sh --postgresql-debs-dir /path/to/debs  (or env ZIOCHUB_POSTGRESQL_DEBS_DIR)
ziochub_postgresql_debs_dir() {
    if [[ -n "${ZIOCHUB_POSTGRESQL_DEBS_DIR:-}" ]]; then
        echo "${ZIOCHUB_POSTGRESQL_DEBS_DIR}"
    else
        echo "${SCRIPT_DIR}/postgresql-debs"
    fi
}

ziochub_pg_generate_password() {
    if command -v openssl &>/dev/null; then
        openssl rand -base64 24 | tr -d '/+=' | head -c 32
    else
        tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c 32
    fi
}

# Return 0 when setup should use an existing PostgreSQL cluster (IT/production or
# already-migrated install) instead of installing from postgresql-debs/.
ziochub_detect_use_existing_postgresql() {
    local env_file="${1:-}"
    local pg_host="${ZIOCHUB_PG_HOST:-127.0.0.1}"
    local pg_port="${ZIOCHUB_PG_PORT:-5432}"

    if [[ -f "${env_file}" ]]; then
        local _h _p
        _h=$(grep -E '^ZIOCHUB_PG_HOST=' "${env_file}" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\r\n' || true)
        _p=$(grep -E '^ZIOCHUB_PG_PORT=' "${env_file}" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\r\n' || true)
        [[ -n "${_h}" ]] && pg_host="${_h}"
        [[ -n "${_p}" ]] && pg_port="${_p}"
    fi

    if pg_isready -h "${pg_host}" -p "${pg_port}" -q 2>/dev/null; then
        return 0
    fi

    # Upgrade path: already on PostgreSQL (cluster may be stopped briefly during setup)
    if [[ -f "${env_file}" ]] && grep -qE '^ZIOCHUB_(PG_PASSWORD|DATABASE_URL)=' "${env_file}" 2>/dev/null; then
        return 0
    fi

    return 1
}

ziochub_install_postgresql_packages() {
    local offline="${1:-false}"
    local use_existing="${2:-false}"

    if pg_isready -h "${ZIOCHUB_PG_HOST}" -p "${ZIOCHUB_PG_PORT}" -q 2>/dev/null; then
        ok "PostgreSQL is already accepting connections — skipping package install."
        return 0
    fi

    if [[ "${use_existing}" == "true" ]]; then
        fail "PostgreSQL is not reachable on ${ZIOCHUB_PG_HOST}:${ZIOCHUB_PG_PORT}." \
             "Install and start PostgreSQL before setup (IT/repo), then re-run with --use-existing-postgresql." \
             "Lab/air-gap without IT: extract ziochub_postgresql_debs_*.zip to a separate directory and run:" \
             "  sudo ./setup.sh --offline --postgresql-debs-dir /path/to/postgresql-debs"
    fi

    if command -v psql &>/dev/null && command -v pg_isready &>/dev/null; then
        ok "PostgreSQL client tools found (server not ready yet — will install/start)."
    fi
    if [[ "${offline}" == "true" ]]; then
        local deb_dir
        deb_dir="$(ziochub_postgresql_debs_dir)"
        if [[ -d "${deb_dir}" ]] && ls "${deb_dir}/"*.deb &>/dev/null 2>&1; then
            local deb_count
            deb_count=$(find "${deb_dir}" -maxdepth 1 -type f -name '*.deb' 2>/dev/null | wc -l)
            info "Installing PostgreSQL from bundled postgresql-debs/ (${deb_count} packages)..."
            if ! compgen -G "${deb_dir}/ssl-cert_"*.deb >/dev/null \
                && ! compgen -G "${deb_dir}/ssl-cert-"*.deb >/dev/null; then
                fail "Offline PostgreSQL bundle is incomplete: missing ssl-cert .deb" \
                     "Rebuild on Ubuntu/Debian matching this server:" \
                     "  sudo ./scripts/download_postgresql_debs.sh" \
                     "  sudo ./package_postgresql_debs.sh" \
                     "Then transfer the new ziochub_postgresql_debs_*.zip to the target."
            fi
            mkdir -p "${deb_dir}/partial"
            dpkg -i "${deb_dir}/"*.deb 2>&1 || true
            if command -v apt-get &>/dev/null; then
                if ! DEBIAN_FRONTEND=noninteractive apt-get install -f -y \
                    -o Dir::Cache::archives="${deb_dir}" \
                    -o Dir::Cache::archives::partial="${deb_dir}/partial"; then
                    fail "Could not configure PostgreSQL from local .deb files only." \
                         "Missing dependencies in postgresql-debs/ — rebuild the PostgreSQL ZIP" \
                         "(sudo ./package_postgresql_debs.sh on a matching Ubuntu/Debian build host)." \
                         "Diagnose: sudo dpkg --configure -a ; dpkg -l | grep -E 'postgresql|ssl-cert|iF|iU'"
                fi
            fi
            dpkg --configure -a 2>/dev/null || true
        else
            fail "Offline install needs PostgreSQL on the target server." \
                 "Production: IT installs PostgreSQL, then: sudo ./setup.sh --offline --use-existing-postgresql" \
                 "Lab/air-gap: extract app ZIP to ziochub_app/ and PostgreSQL ZIP to ziochub_postgresql/, then:" \
                 "  cd ziochub_app && sudo ./setup.sh --offline --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs"
        fi
    else
        info "Installing PostgreSQL (postgresql + postgresql-client)..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-client 2>/dev/null || \
                fail "Could not install PostgreSQL. Install manually: apt install postgresql postgresql-client"
        else
            fail "PostgreSQL client not found and apt-get unavailable. Install postgresql + postgresql-client."
        fi
    fi
    command -v psql &>/dev/null || fail "psql not found after PostgreSQL install."
    ok "PostgreSQL packages ready."
}

ziochub_ensure_postgresql_service() {
    if command -v systemctl &>/dev/null; then
        systemctl enable postgresql 2>/dev/null || true
        systemctl start postgresql 2>/dev/null || service postgresql start 2>/dev/null || true
    fi
    local waited=0
    while ! pg_isready -h "${ZIOCHUB_PG_HOST}" -p "${ZIOCHUB_PG_PORT}" -q 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [[ ${waited} -ge 30 ]]; then
            fail "PostgreSQL is not accepting connections on ${ZIOCHUB_PG_HOST}:${ZIOCHUB_PG_PORT}"
        fi
    done
    ok "PostgreSQL service is ready."
}

ziochub_read_pg_password_from_env_file() {
    local env_file="$1"
    ZIOCHUB_PG_PASSWORD=""
    if [[ -f "${env_file}" ]]; then
        ZIOCHUB_PG_PASSWORD=$(grep -E '^ZIOCHUB_PG_PASSWORD=' "${env_file}" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '\r\n' || true)
    fi
}

ziochub_write_database_env() {
    local env_file="$1"
    local https_port="$2"
    local pg_pass="$3"
    local url="postgresql+psycopg2://${ZIOCHUB_PG_USER}:${pg_pass}@${ZIOCHUB_PG_HOST}:${ZIOCHUB_PG_PORT}/${ZIOCHUB_PG_DB}"

    {
        echo "# ZIoCHub environment (generated by setup.sh)"
        echo "ZIOCHUB_PORT=${https_port}"
        echo "ZIOCHUB_PG_HOST=${ZIOCHUB_PG_HOST}"
        echo "ZIOCHUB_PG_PORT=${ZIOCHUB_PG_PORT}"
        echo "ZIOCHUB_PG_DB=${ZIOCHUB_PG_DB}"
        echo "ZIOCHUB_PG_USER=${ZIOCHUB_PG_USER}"
        echo "ZIOCHUB_PG_PASSWORD=${pg_pass}"
        echo "ZIOCHUB_DATABASE_URL=${url}"
    } > "${env_file}"
    chmod 640 "${env_file}"
    chown "${APP_USER}:${APP_GROUP}" "${env_file}" 2>/dev/null || true
}

ziochub_create_postgresql_role_and_db() {
    local pg_pass="$1"
    info "Creating PostgreSQL role and database (${ZIOCHUB_PG_DB})..."

    sudo -u postgres psql -v ON_ERROR_STOP=1 postgres <<SQL 2>/dev/null || true
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${ZIOCHUB_PG_USER}') THEN
    CREATE ROLE ${ZIOCHUB_PG_USER} LOGIN PASSWORD '${pg_pass}';
  ELSE
    ALTER ROLE ${ZIOCHUB_PG_USER} WITH PASSWORD '${pg_pass}';
  END IF;
END
\$\$;
SQL

    if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${ZIOCHUB_PG_DB}'" 2>/dev/null | grep -q 1; then
        sudo -u postgres createdb -O "${ZIOCHUB_PG_USER}" "${ZIOCHUB_PG_DB}" 2>/dev/null || \
            sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${ZIOCHUB_PG_DB} OWNER ${ZIOCHUB_PG_USER};"
    fi
    ok "PostgreSQL database ${ZIOCHUB_PG_DB} ready."
}

ziochub_load_env_file() {
    local env_file="$1"
    if [[ -f "${env_file}" ]]; then
        set -a
        # shellcheck disable=SC1090
        source "${env_file}"
        set +a
    fi
}

ziochub_run_sqlite_migration_if_needed() {
    local sqlite_path="${DATA_DIR}/ziochub.db"
    local app_dir="$1"
    local venv_dir="$2"

    if [[ ! -f "${sqlite_path}" ]]; then
        info "No legacy SQLite database — skipping SQLite→PostgreSQL migration."
        return 0
    fi

    info "Legacy SQLite database detected — migrating to PostgreSQL..."
    local backup="${DATA_DIR}/backups/pre_pg_migration_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${backup}"
    cp -a "${sqlite_path}" "${backup}/ziochub.db"
    ok "SQLite backup: ${backup}/ziochub.db"

    if ! sudo -u "${APP_USER}" env PATH="${venv_dir}/bin:${PATH}" ZIOCHUB_SKIP_DB_INIT=1 \
        bash -c "cd '${app_dir}' && set -a && source '${DATA_DIR}/ziochub.env' && set +a && \
        python3 '${app_dir}/scripts/migrate_sqlite_to_postgres.py' --sqlite-path '${sqlite_path}' --data-dir '${DATA_DIR}'"; then
        fail "SQLite→PostgreSQL migration failed. See ${DATA_DIR}/migrate_sqlite_to_postgres.log"
    fi
    ok "SQLite→PostgreSQL migration complete."
    ziochub_postgresql_migration_finalize "${app_dir}" "${venv_dir}"
}

ziochub_postgresql_migration_finalize() {
    local app_dir="$1"
    local venv_dir="$2"
    info "Finalizing PostgreSQL (sequences + schema init)..."
    if sudo -u "${APP_USER}" env PATH="${venv_dir}/bin:${PATH}" \
        bash -c "cd '${app_dir}' && set -a && source '${DATA_DIR}/ziochub.env' && set +a && \
        python3 '${app_dir}/scripts/fix_postgres_sequences.py'"; then
        ok "PostgreSQL sequences aligned."
    else
        warn "Sequence fix failed — run: python3 scripts/fix_postgres_sequences.py"
    fi
    ziochub_init_application_database "${app_dir}" "${venv_dir}"
    if sudo -u "${APP_USER}" env PATH="${venv_dir}/bin:${PATH}" \
        bash -c "cd '${app_dir}' && set -a && source '${DATA_DIR}/ziochub.env' && set +a && \
        python3 '${app_dir}/scripts/verify_postgres_migration.py'"; then
        ok "PostgreSQL migration verification passed."
    else
        warn "Migration verification reported issues — see scripts/verify_postgres_migration.py"
    fi
}

ziochub_postgresql_health_check() {
    local app_dir="$1"
    local venv_dir="$2"
    info "PostgreSQL health check (sequences + verification)..."
    if sudo -u "${APP_USER}" env PATH="${venv_dir}/bin:${PATH}" \
        bash -c "cd '${app_dir}' && set -a && source '${DATA_DIR}/ziochub.env' && set +a && \
        python3 '${app_dir}/scripts/fix_postgres_sequences.py'"; then
        ok "PostgreSQL sequences aligned."
    else
        warn "Sequence fix failed — run: python3 scripts/fix_postgres_sequences.py"
    fi
    if sudo -u "${APP_USER}" env PATH="${venv_dir}/bin:${PATH}" \
        bash -c "cd '${app_dir}' && set -a && source '${DATA_DIR}/ziochub.env' && set +a && \
        python3 '${app_dir}/scripts/verify_postgres_migration.py'"; then
        ok "PostgreSQL verification passed."
    else
        warn "Verification reported issues — see scripts/verify_postgres_migration.py"
    fi
}

ziochub_init_application_database() {
    local app_dir="$1"
    local venv_dir="$2"
    info "Initializing PostgreSQL schema as ${APP_USER}..."
    if sudo -u "${APP_USER}" env PATH="${venv_dir}/bin:${PATH}" \
        bash -c "cd '${app_dir}' && set -a && source '${DATA_DIR}/ziochub.env' && set +a && python3 -c 'import app'"; then
        ok "Database initialized."
    else
        warn "Database init failed — check ${DATA_DIR}/ziochub.env and journalctl -u ziochub"
    fi
}
