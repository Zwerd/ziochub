# ZIoCHub Troubleshooting

This guide covers common issues in **offline and online** deployments. All solutions use only local resources (no network required for core fixes).

**Production database:** PostgreSQL (credentials in `/opt/ziochub/data/ziochub.env`). Legacy SQLite (`data/ziochub.db`) exists only until upgrade migration completes.

See also the main [README](../README.md) sections [Database & migration](../README.md#database--migration) and [Inbound integrations (pull)](../README.md#inbound-integrations-pull).

---

## PostgreSQL connection errors

**Symptom:** Service fails to start, or every API call returns 500 with database errors in `journalctl` (`OperationalError`, `could not connect to server`, `password authentication failed`, `FATAL: database "ziochub" does not exist`).

**Checks:**

1. **PostgreSQL service**
   ```bash
   sudo systemctl status postgresql
   sudo systemctl start postgresql
   ```

2. **Environment file** — must exist and be readable by `ziochub`:
   ```bash
   sudo cat /opt/ziochub/data/ziochub.env
   # Expect: ZIOCHUB_DATABASE_URL=postgresql+psycopg2://ziochub:...@127.0.0.1:5432/ziochub
   ```

3. **Test connection as service user**
   ```bash
   sudo -u ziochub bash -c 'set -a && source /opt/ziochub/data/ziochub.env && set +a && \
     /opt/ziochub/venv/bin/python -c "from sqlalchemy import create_engine; \
     import os; e=create_engine(os.environ[\"ZIOCHUB_DATABASE_URL\"]); \
     with e.connect() as c: print(\"OK\")"'
   ```

4. **Role / database missing** — re-run PostgreSQL provisioning or create manually:
   ```bash
   sudo -u postgres psql -c "\du"
   sudo -u postgres psql -c "\l"
   ```
   Fresh install: `sudo ./setup.sh --offline` sources `scripts/postgres_install.sh`.

5. **Wrong password after manual edit** — regenerate role password and update `ziochub.env`, then restart:
   ```bash
   sudo systemctl restart ziochub
   ```

---

## SQLite → PostgreSQL migration failures

**Symptom:** `setup.sh --upgrade` reports migration error, or app still references SQLite after upgrade.

**Log file:** `/opt/ziochub/data/migrate_sqlite_to_postgres.log`

**Pre-migration backup:** `data/backups/pre_pg_migration_<timestamp>/ziochub.db`

**What to do:**

1. Stop the app before manual re-run:
   ```bash
   sudo systemctl stop ziochub
   ```

2. Re-run migration (adjust paths if needed):
   ```bash
   cd /opt/ziochub
   sudo -u ziochub bash -c 'set -a && source /opt/ziochub/data/ziochub.env && set +a && \
     python3 scripts/migrate_sqlite_to_postgres.py \
       --sqlite-path /opt/ziochub/data/ziochub.db'
   sudo -u ziochub bash -c 'set -a && source /opt/ziochub/data/ziochub.env && set +a && \
     python3 scripts/fix_postgres_sequences.py'
   sudo -u ziochub bash -c 'set -a && source /opt/ziochub/data/ziochub.env && set +a && \
     python3 -c "import app"'
   sudo -u ziochub bash -c 'set -a && source /opt/ziochub/data/ziochub.env && set +a && \
     python3 scripts/verify_postgres_migration.py'
   ```

3. On success, SQLite is archived as `ziochub.db.pre_postgresql_<timestamp>` and `ZIOCHUB_DATABASE_URL` is written to `ziochub.env`.

**Recommended (unattended):** `sudo ./setup.sh --upgrade` runs backup, migration, sequence fix, schema init, and verification automatically when `data/ziochub.db` exists.

### Second environment still on SQLite only

Until you run upgrade, the app uses `data/ziochub.db` automatically when **`data/ziochub.env` is absent** (no PostgreSQL credentials). After `setup.sh --upgrade`:

1. Stop service: `sudo systemctl stop ziochub`
2. Run: `sudo ./setup.sh --upgrade` (add `--use-existing-postgresql` or `--postgresql-debs-dir` as needed)
3. Verify: `sudo -u ziochub bash -c 'cd /opt/ziochub && set -a && source data/ziochub.env && set +a && ./venv/bin/python3 scripts/verify_postgres_migration.py'`
4. Start: `sudo systemctl start ziochub`

Dev (`python3 app.py` on port 5000) and prod (Gunicorn 8443) both load `data/ziochub.env` automatically and use the same PostgreSQL when the file exists.

**Compare environments without login** (public API):
```bash
curl -s http://127.0.0.1:5000/api/stats
curl -sk https://127.0.0.1:8443/api/stats
curl -sk https://127.0.0.1:8443/health
```

**Common causes:**

| Cause | Fix |
|-------|-----|
| PostgreSQL not installed (offline) | **Production:** IT installs PG → `setup.sh --offline --use-existing-postgresql`. **Lab:** transfer `ziochub_postgresql_debs_*.zip` from `package_postgresql_debs.sh` into install dir |
| Empty/corrupt SQLite file | Restore from `pre_pg_migration_*` backup |
| Partial migration (tables exist) | Review log; may need DBA to drop/recreate `ziochub` DB and re-run (after backup) |
| `psycopg2` missing in venv | Re-run `setup.sh` or `pip install psycopg2-binary` in `/opt/ziochub/venv` |

---

## Database locked (legacy SQLite only)

**Symptom:** API or UI returns errors like "database is locked" or "database table is locked".

**Applies to:** Legacy SQLite (`data/ziochub.db`) or dev mode (`ZIOCHUB_ALLOW_SQLITE_DEV=true`). **Not applicable to production PostgreSQL.**

**Causes:** SQLite allows one writer at a time. Under load or when many feeds are polled while an analyst submits IOCs, writes can briefly block.

**What to do:**

1. **Single instance** — Ensure only one ZIoCHub app process is running (e.g. one `ziochub.service`). Multiple processes pointing at the same `ziochub.db` will lock each other.
2. **Stale locks** — If the app crashed, restart: `sudo systemctl restart ziochub`
3. **Retries** — The application retries commit on "database is locked" (a few attempts with short backoff). If errors persist, reduce concurrent feed polling or stagger heavy write operations.
4. **Long-term fix** — Run `sudo ./setup.sh --upgrade` to migrate to PostgreSQL.

---

## Inbound integrations (MISP / AdversaryGraph / TAXII pull)

Configure under **Admin → Integrations → Import (pull)**. Monitor **Feed Pulse → Pull State** in the main app.

### General checks

```bash
# MISP timer (if using systemd job)
systemctl status ziochub-misp-sync.timer
journalctl -u ziochub-misp-sync -n 30 --no-pager

# TAXII pull timer (if enabled)
systemctl status ziochub-taxii-sync.timer
journalctl -u ziochub-taxii-sync -n 30 --no-pager

# In-app schedulers (MISP, AdversaryGraph) — app journal
journalctl -u ziochub -n 100 --no-pager | grep -iE 'misp|adversarygraph|taxii|sync'
```

| Issue | What to check |
|-------|----------------|
| Pull State shows "never" | Connector **Enabled** = Yes; **Test Connection** succeeds |
| No new IOCs | Lookback days, tag/type filters, published-only (MISP); dedup skips existing values |
| Lock / skip messages | Another sync in progress; DB lock auto-expires after ~10 minutes |
| Wrong analyst | **Sync analyst username** setting (e.g. `misp_sync`, `adversarygraph_sync`) |

### MISP pull

- **URL + API key** in Integrations → Import → MISP pull
- **PyMISP** must be installed in venv (`pip show pymisp`)
- Firewall: ZIoCHub server must reach MISP HTTPS port
- Manual test: **Sync Now** on the MISP tab

### AdversaryGraph pull

- **API URL** must point to the **FastAPI backend** (e.g. `http://host:8000`), not the React UI port
- If AdversaryGraph auth/OIDC proxy is enabled, set **X-Auth-User** and **X-Auth-Roles** headers in the form
- **Pull YARA** toggle controls Detection Studio imports; YARA may stay **pending** when **Workflow → YARA auto-publish** is off
- Endpoints used: `/api/health`, `/api/ioc/library`, `/api/pipeline/detections/versions?format=yara`
- Icon in Feed Pulse: `/static/img/vendors/adversarygraph.png`

### Remote TAXII 2.1 pull

- Separate from ZIoCHub's **TAXII server** (Export tab)
- Enable `ziochub-taxii-sync.timer` after configuration
- Verify discovery URL, API root, collection ID, and credentials

---

## Service won't start

**Symptom:** `systemctl start ziochub` fails or the service exits immediately (e.g. exit code 255, status=3, or auto-restart loop).

**Checks:**

1. **ModuleNotFoundError (Missing Python modules)**  
   **Symptom:** Service enters auto-restart loop with `ModuleNotFoundError: No module named 'constants'` (or similar).
   
   **Common Causes:**
   - Missing Python modules in offline package (`constants.py`, `models.py`, `extensions.py`)
   - Missing `utils/` directory
   - Incomplete package build
   
   **Solution:**
   ```bash
   # Verify package contents (before installation)
   unzip -l ziochub_installer.zip | grep -E "(constants|models|extensions|utils)"
   
   # Or use integrity test script
   chmod +x test_package_integrity.sh
   ./test_package_integrity.sh ziochub_installer.zip
   
   # Check installed files (after installation)
   ls -la /opt/ziochub/*.py
   ls -la /opt/ziochub/utils/
   
   # Verify imports
   sudo -u ziochub /opt/ziochub/venv/bin/python -c "from constants import *"
   sudo -u ziochub /opt/ziochub/venv/bin/python -c "from models import *"
   sudo -u ziochub /opt/ziochub/venv/bin/python -c "from extensions import *"
   
   # Or use import test script
   chmod +x test_imports.sh
   sudo ./test_imports.sh /opt/ziochub/venv
   
   # If files are missing, rebuild package
   ./package_offline.sh
   ```

2. **Building Package Offline**  
   **Symptom:** `./package_offline.sh` fails with "No internet connection" or download errors when trying to build package on an offline machine.
   
   **Solution:** The script supports full offline mode if you have an existing `packages/` directory with Python wheel files:
   
   ```bash
   # Option 1: Copy packages from a previous build
   cp -r /path/to/previous/build/packages/ ./packages/
   ./package_offline.sh  # Will use existing packages (OFFLINE MODE)
   
   # Option 2: Build on machine with internet, then transfer
   ./package_offline.sh  # Downloads packages on online machine
   # Copy entire project (including packages/) to offline machine
   ./package_offline.sh  # Uses existing packages on offline machine
   ```
   
   **Note:** The script automatically detects existing `packages/` directory. No internet required if `packages/` exists.

3. **Venv Creation Fails During Installation**  
   **Symptom:** `sudo ./setup.sh --offline` fails with error about Python venv module not being available.
   
   **Solution:**
   ```bash
   sudo apt-get update
   sudo apt-get install python3-venv
   # Or: sudo apt-get install python3.10-venv
   sudo ./setup.sh --offline
   ```

4. **PostgreSQL not available (fresh/offline install)**  
   - **Production:** install PostgreSQL from IT/repo first, then `sudo ./setup.sh --offline --use-existing-postgresql`  
   - **Lab/air-gap:** build `sudo ./package_postgresql_debs.sh`, extract that ZIP next to `setup.sh`, then `sudo ./setup.sh --offline`

5. **User and permissions**  
   The service runs as user `ziochub`. Data directory must be writable:
   ```bash
   sudo chown -R ziochub:ziochub /opt/ziochub
   sudo chmod -R u+rwX,g+rX,o-rwx /opt/ziochub/data
   ```

6. **Python and venv** — Run manually to see tracebacks:
   ```bash
   sudo -u ziochub bash -c 'set -a && source /opt/ziochub/data/ziochub.env && set +a && \
     /opt/ziochub/venv/bin/python /opt/ziochub/app.py'
   ```

7. **Custom data directory** — Set in systemd unit:
   ```ini
   Environment=ZIOCHUB_DATA_DIR=/your/data/path
   ```
   Ensure path exists and is writable by `ziochub`.

8. **Logs** — See [Where to find logs](#where-to-find-logs) below.

---

## Where to find logs

| Location | Content |
|---------|--------|
| **systemd journal** | All application output (gunicorn, Flask, tracebacks). **Primary place to debug.** |
| **CEF audit file** | Audit events (logins, avatar upload, push attempts, etc.) |
| **Migration log** | `data/migrate_sqlite_to_postgres.log` (SQLite → PG upgrade) |

```bash
# Last 100 lines
journalctl -u ziochub -n 100 --no-pager

# Follow live (e.g. while reproducing an error)
journalctl -u ziochub -f

# Today only
journalctl -u ziochub --since today --no-pager
```

**Audit log:** `/opt/ziochub/data/audit_cef.log` (48-hour rotation).

### Outbound integrations (IOC / YARA push)

Outbound push attempts are recorded as **CEF audit events** and **Feed Pulse → Connections** telemetry. Routine success/failure may **not** appear in `journalctl` unless Python raises an exception.

```bash
sudo tail -n 200 /opt/ziochub/data/audit_cef.log
sudo grep -E 'ioc_push_|yara_push_|yara_delete_' /opt/ziochub/data/audit_cef.log | tail -n 100
```

If UDP syslog is enabled (Admin → Settings → Syslog), check your SIEM for the same CEF actions.

---

## Avatar upload / "Network error"

**Symptom:** When uploading a profile picture (Profile or Admin > Users), the UI shows **"Network error"** in red.

The message means the browser's request to the server failed (no response, 4xx/5xx, or timeout). Debug on the **server**:

1. **Check logs** (see [Where to find logs](#where-to-find-logs)):
   ```bash
   journalctl -u ziochub -n 50 --no-pager
   ```
   Reproduce the upload, then look for `api_profile_avatar_upload failed` or `api_admin_user_avatar_upload failed` and the Python traceback.

2. **Permissions** — The process runs as user `ziochub` and must write to `static/avatars/`:
   ```bash
   sudo chown -R ziochub:ziochub /opt/ziochub/static/avatars
   sudo chmod 755 /opt/ziochub/static/avatars
   ```

3. **File size** — Default max upload is 16 MB (`MAX_CONTENT_LENGTH`). Very large images can return 413.

4. **Lab users** — Avatars from `create_lab_users.py` are copied only if image files exist in `users/` (e.g. `users/alice.jpg`).

---

## Permissions (files owned by root)

**Symptom:** After installing or copying files as root, the app reports "Permission denied" on `data/`, PostgreSQL env file, `data/Main/`, or `audit_cef.log`.

**Fix:**

```bash
sudo chown -R ziochub:ziochub /opt/ziochub
sudo chmod -R u+rwX,g+rX,o-rwx /opt/ziochub/data
sudo systemctl restart ziochub
```

---

## Backup and restore (offline, local)

ZIoCHub includes a **local-only** backup script. No network or cloud is used.

- **Script:** `backup_ziochub.sh`
- **Output:** `data/backups/<timestamp>/` containing:
  - `ziochub.pgdump` (PostgreSQL custom format)
  - `ziochub.sql` (plain SQL dump)
  - Legacy `ziochub.db` (if still present)
  - SSL certs, YARA rules, allowlist, CEF audit log
- **Retention:** Last 30 daily backups (timer-managed)

**Run manually:**

```bash
sudo -u ziochub ZIOCHUB_DATA_DIR=/opt/ziochub/data /opt/ziochub/backup_ziochub.sh
```

**Schedule with systemd (installed by setup):**

```bash
sudo systemctl enable ziochub-backup.timer
sudo systemctl start ziochub-backup.timer
```

**Restore PostgreSQL (example — stops app, destroys current DB contents):**

```bash
sudo systemctl stop ziochub
sudo -u ziochub bash -c 'set -a && source /opt/ziochub/data/ziochub.env && set +a && \
  pg_restore -h 127.0.0.1 -U ziochub -d ziochub -c /path/to/backup/ziochub.pgdump'
sudo systemctl start ziochub
```

---

## HTTP redirect not working

```bash
systemctl status ziochub-redirect
```

Ensure SSL certificates are uploaded via **Admin → Certificate**, then restart:

```bash
sudo systemctl restart ziochub ziochub-redirect
```

---

## Reset all data

```bash
sudo systemctl stop ziochub
cd /opt/ziochub
python reset_data.py --all --yes
sudo systemctl start ziochub
```

**Warning:** Clears application data including PostgreSQL tables (when configured). Take a backup first.

---

## Full reinstall

```bash
sudo ./uninstall.sh --backup   # Saves data to /opt/ziochub_backup_*
sudo ./setup.sh --offline      # Fresh install (PostgreSQL provisioned)
```

**Note:** `uninstall.sh` does not remove the PostgreSQL cluster; only the ZIoCHub app and data directory (unless you choose to keep backups elsewhere).

---

## Security note: displaying user content

Comments and other user-supplied fields are sent by the API as plain text and are rendered in the browser. The UI uses `escapeHtml()` in JavaScript when inserting them into the DOM. If you add **server-side** templates that render user content (e.g. comments), always use Jinja2's escape filter: `{{ value | e }}` so HTML/script is not executed.
