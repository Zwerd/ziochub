# Authentication — Offline & Air-Gapped Deployment

This document describes how to run ZIoCHub **fully offline** with no AD, no LDAP, and no network access.

---

## Overview

ZIoCHub supports three authentication modes:

| AUTH_MODE | Description |
|-----------|-------------|
| `local_only` | Local users only. No LDAP. **Use for fully offline.** |
| `ldap` | LDAP/AD only. No local fallback. |
| `ldap_with_local_fallback` | Try LDAP first; if unreachable, fall back to local users. |

---

## Running Fully Offline (No AD, No LDAP)

### 1. Use Local-Only Mode

- Set **Auth Mode** to **Local Only** in Admin → Settings.
- Or set environment variable: `AUTH_MODE=local_only`

### 2. Default Admin User

On first run, ZIoCHub creates a default admin user:

- **Username:** `admin`
- **Password:** `admin` (or `ADMIN_DEFAULT_PASSWORD` env var)

**Important:** Change the admin password after first login.

### 3. Create Local Users

- Log in as admin.
- Go to **Admin → Users**.
- Create local users with usernames and passwords.
- Local users work without any network or LDAP.

### 4. No Network Required

- Database: SQLite (local file)
- Auth: Local users only (no LDAP, no AD)
- Static assets: Served locally (no CDN)
- GeoIP: Optional; system works without it

---

## Environment Variables (Phase 6)

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_MODE` | Override auth mode: `local_only`, `ldap`, `ldap_with_local_fallback` | From Admin Settings |
| `DEV_MODE` | Set to `1` for dev features (dev user, LDAP mock) | `0` |
| `FLASK_DEBUG` | Enable Flask debug mode (also enables dev features) | `false` |
| `ADMIN_DEFAULT_PASSWORD` | Default password for initial admin user | `admin` |

---

## Dev Mode (Development Only)

When `DEV_MODE=1` or `FLASK_DEBUG=true`:

- **Dev login:** Use `devuser` / `dev` to auto-login as admin (no password check).
- **LDAP mock:** Use `ldaptest` / `ldaptest` to simulate LDAP when LDAP URL is not configured.
- **Graceful LDAP failure:** If LDAP is unreachable, the app does not crash; it falls back to local users when `auth_mode` is `ldap_with_local_fallback`.

**Do not enable dev mode in production.**

---

## LDAP Unreachable (Phase 6.3)

When LDAP is configured but unreachable (offline, DC down, wrong URL):

1. With **ldap_with_local_fallback**: Local users continue to work. A warning is logged.
2. With **ldap** only: Login fails until LDAP is reachable.
3. With **local_only**: LDAP is never used; no impact.

---

## Quick Start (Offline)

```bash
# 1. Set local-only mode (optional; it's the default)
export AUTH_MODE=local_only

# 2. Run the app
python app.py

# 3. Open http://localhost:5000
# 4. Log in: admin / admin
# 5. Change password in Admin → Users
```
