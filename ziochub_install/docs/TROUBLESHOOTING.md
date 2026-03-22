# ZIoCHub — Troubleshooting

This guide covers common issues in **offline and online** deployments. All solutions use only local resources (no network required for core fixes).

---

## Database locked

**Symptom:** API or UI returns errors like "database is locked" or "database table is locked".

**Causes:** SQLite allows one writer at a time. Under load or when many feeds are polled while an analyst submits IOCs, writes can briefly block.

**What to do:**

1. **Single instance** — Ensure only one ZIoCHub app process is running (e.g. one `ziochub.service`). Multiple processes (e.g. dev + production) pointing at the same `ziochub.db` will lock each other.
2. **Stale locks** — If the app crashed, SQLite usually releases the lock when the process exits. Restart the service:  
   `sudo systemctl restart ziochub`
3. **Retries** — The application retries commit on "database is locked" (a few attempts with short backoff). If errors persist, reduce concurrent feed polling or stagger heavy write operations.

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
   # If you have packages/ from a previous build:
   cp -r /path/to/previous/build/packages/ ./packages/
   ./package_offline.sh  # Will use existing packages (OFFLINE MODE)
   
   # Option 2: Build on machine with internet, then transfer
   # Build on a machine with internet:
   ./package_offline.sh  # Downloads packages
   # Then copy the entire project (including packages/) to offline machine
   # On offline machine:
   ./package_offline.sh  # Will detect and use existing packages
   
   # Verify offline mode is working:
   # Script should show: "Found existing packages/ directory with X wheel files (OFFLINE MODE)"
   ```
   
   **Note:** The script automatically detects existing `packages/` directory and uses it instead of downloading. No internet connection required if this directory exists.

3. **Venv Creation Fails During Installation**  
   **Symptom:** `sudo ./setup.sh --offline` fails with error about Python venv module not being available.
   
   **Solution:** Install the python3-venv package on the target server:
   
   ```bash
   # For Ubuntu/Debian:
   sudo apt-get update
   sudo apt-get install python3-venv
   
   # Or for a specific Python version (e.g., Python 3.10):
   sudo apt-get install python3.10-venv
   
   # Then run the installer again:
   sudo ./setup.sh --offline
   ```
   
   **Note:** The installer will display a clear error message with instructions if venv creation fails. Simply install the required package and rerun the installer.

3. **User and permissions**  
   The service runs as user `ziochub`. Data directory must be writable by that user:
   ```bash
   sudo chown -R ziochub:ziochub /opt/ziochub
   sudo chmod -R u+rwX,g+rX,o-rwx /opt/ziochub/data
   ```

3. **Python and venv**  
   Run manually as the service user to see tracebacks:
   ```bash
   sudo -u ziochub /opt/ziochub/venv/bin/python /opt/ziochub/app.py
   ```
   Fix any missing modules (e.g. re-run `setup.sh` or install from `requirements.txt`).

4. **Data directory**  
   If you use a custom path, set it in the service:
   ```ini
   Environment=ZIOCHUB_DATA_DIR=/your/data/path
   ```
   and ensure that path exists and is writable by `ziochub`.

5. **Logs** — See [Where to find logs](#where-to-find-logs) below.

---

## Where to find logs

| Location | Content |
|---------|--------|
| **systemd journal** | All application output (gunicorn, Flask, tracebacks). **Primary place to debug.** |
| **CEF audit file** | Audit events (logins, avatar upload, etc.) if logging is enabled. |

```bash
# Last 100 lines
journalctl -u ziochub -n 100 --no-pager

# Follow live (e.g. while reproducing an error)
journalctl -u ziochub -f

# Today only
journalctl -u ziochub --since today --no-pager
```

**Audit log:** `/opt/ziochub/data/audit_cef.log` (48-hour rotation).

---

## Avatar upload / "Network error"

**Symptom:** When uploading a profile picture (Profile or Admin > Users), the UI shows **"Network error"** in red.

The message means the browser’s request to the server failed (no response, 4xx/5xx, or timeout). Debug on the **server**:

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

4. **Lab users** — Avatars from `create_lab_users.py` are copied only if image files exist in `users/` (e.g. `users/alice.jpg`). To add avatars later, either put images in `users/` and re-run the script, or use the UI; if the UI shows "Network error", use the logs and permissions above.

---

## Permissions (files owned by root)

**Symptom:** After installing or copying files as root, the app reports "Permission denied" on `ziochub.db`, `data/Main/`, or `audit.log`.

**Fix:** Give ownership of app and data to the service user:

```bash
sudo chown -R ziochub:ziochub /opt/ziochub
sudo chmod -R u+rwX,g+rX,o-rwx /opt/ziochub/data
```

Then restart:

```bash
sudo systemctl restart ziochub
```

---

## Backup (offline, local)

ZIoCHub includes a **local-only** backup script. No network or cloud is used.

- **Script:** `backup_ziochub.sh` (copies `ziochub.db` to `data/backups/`, keeps last 30 days).
- **Data directory:** Uses `ZIOCHUB_DATA_DIR` if set; otherwise defaults to `/opt/ziochub/data` (same as production install).

**Run manually:**

```bash
# As ziochub user (recommended)
sudo -u ziochub ZIOCHUB_DATA_DIR=/opt/ziochub/data /opt/ziochub/backup_ziochub.sh
```

**Schedule with systemd (optional, installed by setup):**

```bash
sudo systemctl enable ziochub-backup.timer
sudo systemctl start ziochub-backup.timer
```

**Schedule with cron (alternative):**

```cron
0 2 * * * ziochub ZIOCHUB_DATA_DIR=/opt/ziochub/data /opt/ziochub/backup_ziochub.sh
```

---

## Security note: displaying user content

Comments and other user-supplied fields are sent by the API as plain text and are rendered in the browser. The UI uses `escapeHtml()` in JavaScript when inserting them into the DOM. If you add **server-side** templates that render user content (e.g. comments), always use Jinja2’s escape filter: `{{ value | e }}` so HTML/script is not executed.
