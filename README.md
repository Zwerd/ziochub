# ThreatGate v2.0 Beta - Commander Edition

ThreatGate is a **modern IOC & YARA Management Platform** built for SOC operations. Analysts submit indicators, ThreatGate stores them in a SQLite database, and security devices ingest **plain-text feeds** for enforcement. Designed for **air-gapped / offline** environments.

---

## Features

- **Authentication & User Management**: Local accounts, optional LDAP/AD integration, admin roles, profile (display name, avatar), change password, optional "must change password" on first login
- **MISP Integration**: Automatic IOC pull from a local MISP instance with configurable intervals
- **Champs Analysis**: Analyst leaderboard, multiple scoring methods (Weighted, Flat, By Type, Campaign Focus, Time Decay, Quality, Goal-Based, Smart/Effort), streak bonuses, team goals, rank tracking, activity spotlight, news ticker
- **Feed Pulse**: Real-time incoming/outgoing IOC monitoring with anomaly detection and analyst exclusions
- **Campaign Management**: Visual graph (vis.js) of campaigns and associated IOCs
- **YARA Rule Management**: Upload, approval workflow, quality scoring (10–50 pts), campaign linking
- **Intelligence Reports**: Period-based reports (day/week/month) with KPIs, type distribution, feed health, analyst activity, export to PDF
- **Multi-vendor Feeds**: Standard, Palo Alto (EDL), Checkpoint (CSV) feed formats
- **SSL/TLS & HTTPS**: Certificate upload via Admin UI, automatic HTTP-to-HTTPS redirect
- **IOC History**: Full lifecycle tracking per IOC (created, edited, deleted, expired, excluded, unexcluded)
- **IOC Notes**: Analyst notes per IOC (type+value) for knowledge sharing; notes survive IOC deletion cycles
- **Allowlist / Safety Net**: Admin-managed allowlist (raw text); prevents blocking of critical infrastructure
- **Sanity Checks**: Automatic anomaly detection (local IPs, short domains, critical infra)
- **GeoIP Intelligence**: Country, TLD, and email domain analytics from active IOCs; Rare Find badges for first-ever country/TLD/email domain
- **CEF / Syslog**: Optional CEF-format audit logging with 48-hour local rotation and UDP syslog forwarding (Admin Settings)
- **Multi-language**: English and Hebrew (i18n)
- **100% Offline**: No external network calls. All assets served locally

---

## Table of Contents

- [Installation](#installation)
- [Ports & Network](#ports--network)
- [Systemd Services](#systemd-services)
- [UI Screens Overview](#ui-screens-overview)
- [Feed Endpoints](#feed-endpoints)
- [API Endpoints](#api-endpoints)
- [MISP Integration](#misp-integration)
- [Data Model](#data-model)
- [Configuration](#configuration)
- [Maintenance](#maintenance)
- [Admin Scripts](#admin-scripts)
- [Security](#security)
- [Project Architecture](#project-architecture)
- [Offline Deployment](#offline-deployment)
- [Troubleshooting](#troubleshooting)
- [Version](#version)

---

## Installation

### Option 1: Online (Linux with Internet)

```bash
# Copy project to server
scp -r ThreatGate/ user@server:/tmp/

# Install
cd /tmp/ThreatGate
sudo ./setup.sh
```

### Option 2: Offline (Air-Gapped)

```bash
# On dev machine (with internet):
./package_offline.sh
# Transfer threatgate_installer.zip to server

# On target server:
unzip threatgate_installer.zip -d threatgate_install
cd threatgate_install
sudo ./setup.sh --offline
```

### Option 3: Upgrade Existing

```bash
sudo ./setup.sh --upgrade
# or
sudo ./setup.sh --upgrade --offline
```

### Local Development

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
# Open http://127.0.0.1:5000
```

Default credentials: `admin` / `admin`

---

## Ports & Network

| Port | Protocol | Service | Description |
|------|----------|---------|-------------|
| **8443** | HTTPS | ThreatGate | Main application (gunicorn + SSL) |
| **8080** | HTTP | Redirect | 301 redirect to HTTPS on 8443 |
| **5000** | HTTP | Dev only | Flask development server (`python app.py`) |

- If SSL certificates are configured (Admin > Certificate), port 8443 serves HTTPS automatically
- If no certificates exist, port 8443 serves plain HTTP
- The HTTP redirect server on port 8080 runs alongside the main service

---

## Systemd Services

| Unit | Type | Description |
|------|------|-------------|
| `threatgate.service` | Main | Gunicorn application server (port 8443) |
| `threatgate-redirect.service` | Main | HTTP-to-HTTPS redirect (port 8080) |
| `threatgate-cleaner.timer` | Timer | Expired IOC cleanup (daily) |
| `threatgate-backup.timer` | Timer | Database + SSL + YARA backup (daily) |
| `threatgate-misp-sync.timer` | Timer | MISP IOC pull (interval set by admin) |

```bash
# Common commands
sudo systemctl status threatgate
sudo systemctl restart threatgate
sudo journalctl -u threatgate -f
```

---

## UI Screens Overview

### Live Stats
Real-time dashboard with IOC counts, Top Countries / TLDs / Email Domains leaderboards, and live IOC feed.

### Search & Investigate
Full-text search across IOCs with filters (value, type, ticket, user, date, expiration status). Edit, delete, view history.

### Submit IOCs
Single and bulk submission: auto-type detection, input cleaning (refanger), TTL, campaign assignment, allowlist validation. Bulk: CSV and TXT import with preview/staging, auto-detection, metadata extraction, and conflict handling.

### Feed Pulse
Real-time feed health monitoring: incoming IOCs, outgoing (expired), deleted, sanity anomalies with exclude/un-exclude.

### YARA Manager
Upload, preview, edit, approve/reject YARA rules. Quality scoring, campaign linking, syntax highlighting.

### Champs Analysis
Analyst leaderboard with weighted scoring, streak bonuses, rank trends, team goals, activity spotlight, news ticker.

### Campaign Graph
Interactive vis.js graph of campaigns linked to IOCs and YARA rules. Create, link, export to CSV.

### Hunter's Playbook
Customizable quick-links panel for external investigation tools.

### Intelligence Reports
Period-based reports (day/week/month): executive KPIs, type distribution, feed health score, analyst activity, comparisons vs. previous period. Export to PDF (html2canvas + jsPDF).

### Profile & Change Password
User profile (display name, avatar, role description, email) and change-password flow; admins can enforce "must change password" for users.

### Admin Panel
- **Users**: Create, edit, deactivate users; avatar management; system users marked separately
- **Settings**: Auth mode (local/LDAP), LDAP config, MISP integration, CEF/Syslog UDP (optional)
- **Allowlist**: Edit raw allowlist file (known-good / critical assets)
- **Certificate**: SSL/TLS certificate upload for HTTPS
- **Scoring**: Champs scoring method (Weighted, Flat, By Type, Campaign Focus, Time Decay, Quality, Goal-Based, Smart)

---

## Feed Endpoints

### Standard Feeds

| Endpoint | Content |
|----------|---------|
| `/feed/ip` | IP addresses |
| `/feed/domain` | Domains |
| `/feed/url` | URLs (with protocol) |
| `/feed/hash` | All hashes |
| `/feed/md5` | MD5 only |
| `/feed/sha1` | SHA1 only |
| `/feed/sha256` | SHA256 only |

### Palo Alto (EDL)

| Endpoint | Note |
|----------|------|
| `/feed/pa/ip` | Standard |
| `/feed/pa/domain` | Standard |
| `/feed/pa/url` | **URLs without protocol** |
| `/feed/pa/md5`, `/sha1`, `/sha256` | Standard |

### Checkpoint (CSV)

| Endpoint | Format |
|----------|--------|
| `/feed/cp/ip`, `/domain`, `/url`, `/hash`, `/md5`, `/sha1`, `/sha256` | CSV with observe numbers |

### YARA Feeds

| Endpoint | Description |
|----------|-------------|
| `/feed/yara-list` | List of approved YARA filenames |
| `/feed/yara-content/<filename>` | Raw YARA rule content |

All feeds return only **active (non-expired) IOCs**. Content-Type: `text/plain`.

---

## MISP Integration

ThreatGate can pull IOC attributes from a local MISP instance automatically.

### Configuration (Admin > Settings > MISP Integration)

| Setting | Description |
|---------|-------------|
| MISP Sync Enabled | Enable/disable automatic sync |
| MISP URL | URL of the MISP instance |
| API Key | MISP API authentication key |
| Verify SSL | Verify MISP server certificate |
| Lookback (days) | How far back to fetch attributes |
| Auto-sync interval (min) | Pull frequency (minimum 5 minutes) |
| Filter by Tags | Comma-separated MISP tags to filter |
| Filter Attribute Types | Comma-separated MISP types (e.g. `ip-src, domain, sha256`) |
| Published Events Only | Only fetch from published MISP events |
| Default TTL | Expiration for imported IOCs (days, or `permanent`) |
| Sync Analyst Username | Username recorded as analyst (default: `misp_sync`) |
| Exclude from Champs | Hide MISP sync user from Champs leaderboard |

### Supported MISP Attribute Types

| MISP Type | ThreatGate Type |
|-----------|-----------------|
| `ip-src`, `ip-dst`, `ip-src\|port`, `ip-dst\|port` | IP |
| `domain`, `hostname` | Domain |
| `url`, `uri`, `link` | URL |
| `md5`, `sha1`, `sha256`, `sha512`, `ssdeep`, `imphash` | Hash |
| `email-src`, `email-dst`, `email` | Email |

### How It Works

1. Systemd timer triggers `misp_sync_job.py` every 5 minutes
2. The job checks admin-configured interval and skips if not enough time has passed
3. Fetches attributes from MISP via `pymisp`
4. Validates each IOC (same regex validation as manual submission)
5. Inserts new IOCs with deduplication, logs to `ioc_history`
6. A DB-based lock prevents concurrent syncs (auto-expires after 10 minutes)

The `misp_sync` user is created as `source='system'` and cannot log in.

---

## Data Model

SQLite database: `data/threatgate.db`

| Table | Description |
|-------|-------------|
| `users` | User accounts (username, password_hash, source, is_admin, is_active, must_change_password, last_login_at) |
| `user_profiles` | Display name, avatar_path, role_description, email |
| `user_sessions` | Login/logout tracking (IP, login_at, logout_at) |
| `iocs` | IOC records (type, value, analyst, ticket_id, comment, expiration, campaign_id, tags, user_id, submission_method, country_code, tld, email_domain, rare_find_type) |
| `ioc_history` | Lifecycle events per IOC (created, edited, deleted, expired, excluded, unexcluded); payload JSON |
| `ioc_notes` | Analyst notes per IOC (ioc_type, ioc_value, user_id, content); keyed by type+value, survive deletion |
| `campaigns` | Campaign metadata (name, description, dir ltr/rtl) |
| `yara_rules` | YARA rule metadata, quality_points, status (pending/approved/rejected) |
| `sanity_exclusions` | Analyst-excluded Feed Pulse anomalies (value, ioc_type, anomaly_type) |
| `system_settings` | Key-value store (auth, LDAP, MISP, Champs, syslog UDP) |
| `activity_events` | Champs activity log (ioc_submit, yara_upload, rank_change, goal_progress, deletion) |
| `team_goals` | Champs team goals (target, current, period, goal_type) |
| `champ_rank_snapshots` | Daily rank snapshots for trend tracking |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_PORT` | `5000` | Dev server port |
| `FLASK_DEBUG` | `false` | Debug mode |
| `SECRET_KEY` | random | Flask secret key (set in production) |
| `THREATGATE_DATA_DIR` | `<app>/data` | Data directory override |
| `THREATGATE_MAX_CONTENT_MB` | `16` | Max upload size |
| `ADMIN_DEFAULT_PASSWORD` | `admin` | Initial admin password |
| `THREATGATE_PORT` | `8443` | Production gunicorn port |
| `THREATGATE_WORKERS` | `3` | Gunicorn worker count |
| `REDIRECT_HTTP_PORT` | `8080` | HTTP redirect listen port |
| `REDIRECT_HTTPS_PORT` | `8443` | HTTPS redirect target port |

### Admin Settings (Web UI)

- **Auth Mode**: `local_only`, `ldap_only`, `ldap_with_local_fallback`
- **LDAP**: URL, Base DN, Bind DN, User Filter
- **MISP**: URL, API key, filters, sync interval, TTL, Champs exclusion
- **Syslog / CEF**: Optional UDP syslog (host, port) for CEF audit events
- **Champs**: Scoring method (Admin > Scoring), ticker messages, team goals

---

## Maintenance

### Backup

Automated via `threatgate-backup.timer` (daily). Backs up:
- `threatgate.db` (database)
- `data/ssl/*.pem` (SSL certificates)
- `data/YARA/*.yar` (YARA rules)
- `data/allowlist.txt`

Retention: 30 days. Manual run:
```bash
sudo -u threatgate /opt/threatgate/backup_threatgate.sh
```

### Expired IOC Cleanup

Automated via `threatgate-cleaner.timer`. Removes expired IOCs and logs each deletion to `ioc_history` with `event_type='expired'`.

### Data Reset

```bash
cd /opt/threatgate
sudo systemctl stop threatgate

# Interactive (asks per category)
python reset_data.py

# Full wipe (IOCs, YARA, campaigns, history, champs, sessions, MISP settings, users)
python reset_data.py --all --yes

# Selective
python reset_data.py --iocs --yara --history --yes
python reset_data.py --settings   # Reset MISP settings only

sudo systemctl start threatgate
```

### Lab User Setup

```bash
python create_lab_users.py
# Prompts for a common password, creates predefined analyst accounts
```

---

## Admin Scripts

When using a full deployment package (e.g. offline installer), the following scripts may be provided:

| Script | Description |
|--------|-------------|
| `setup.sh` | Production installer (online/offline/upgrade) |
| `uninstall.sh` | Full removal (services, files, user) |
| `package_offline.sh` | Build offline installer ZIP |
| `backup_threatgate.sh` | Manual backup (DB, SSL, YARA, allowlist) |
| `reset_data.py` | Wipe operational data (granular or full) |
| `create_lab_users.py` | Create lab analyst accounts |
| `cleaner.py` | Remove expired IOCs (runs via systemd timer) |
| `misp_sync_job.py` | MISP sync job (runs via systemd timer) |
| `http_redirect.py` | HTTP-to-HTTPS redirect server |
| `start.sh` | Gunicorn launcher with auto SSL detection |

For development, only the application is required: `python app.py` (see [Local Development](#local-development)).

---

## Security

- **Authentication**: All pages and API endpoints require login (Flask-Login)
- **Passwords**: Scrypt hashing via werkzeug
- **LDAP**: Optional AD/LDAP authentication with local fallback
- **SSL/TLS**: Certificate upload via admin UI, gunicorn serves HTTPS directly
- **HTTP Redirect**: Automatic 301 redirect from HTTP to HTTPS
- **System Users**: MISP sync user has `source='system'`, `password_hash=None` (cannot log in)
- **Input Validation**: Regex validation on all IOC types, refanger for obfuscated input
- **SQL Injection**: SQLAlchemy ORM with parameterized queries
- **Allowlist**: Prevents blocking critical infrastructure assets
- **Audit Log**: CEF format; local file with 48-hour rotation; optional UDP syslog (Admin > Settings)
- **Feed Endpoints**: Public (no auth). Restrict access via firewall rules
- **Offline**: No external network calls. All assets local

---

## Project Architecture

### Backend

```
app.py              Main Flask application
models.py           SQLAlchemy models
extensions.py       Flask extensions (db)
constants.py        Application constants (VERSION, IOC_FILES, limits)
config.py           Configuration (optional)

routes/
  admin.py          Admin API (users, settings, certificate, MISP, allowlist)
  auth.py           Login, logout, profile, change password, LDAP health
  champs.py         Champs leaderboard, team goals, ticker
  campaigns.py      Campaign CRUD and graph API
  feeds.py          Feed generation (standard, PA, CP, YARA)
  ioc.py            IOC submit (single/bulk) API
  reports.py        Intelligence reports (period-based stats, PDF export)
  search.py         Search, edit, delete, history API
  stats.py           Live stats counts, geo/TLD/email intelligence
  yara.py            YARA rule management API

utils/
  validation.py       IOC regex validation and type detection
  refanger.py         Input cleaning (defang reversal)
  allowlist.py        Allowlist loading and checking
  feed_helpers.py     Feed formatting helpers
  yara_utils.py       YARA file path utilities
  validation_warnings.py   IOC submission warnings
  validation_messages.py   Error message constants
  sanity_checks.py    Feed Pulse anomaly detection
  auth.py             Password hashing (scrypt)
  decorators.py       @login_required, @admin_required
  ldap_auth.py        LDAP/AD authentication
  champs.py           Analyst scoring, ranking, badges, XP
  misp_sync.py        MISP fetch, validate, import, lock
  ioc_decode.py       Text extraction for bulk IOC parsing
  cef_logger.py       CEF audit logging (local file + optional UDP syslog)
  mentorship.py       SOC Mentorship Insights Engine (behavioral analysis, 45 rules)
```

### Frontend

Single-Page Application in `templates/index.html` with lazy-loaded JS modules:

| Module | Purpose |
|--------|---------|
| `static/js/api.js` | Centralized API client |
| `static/js/utils.js` | HTML escaping, clipboard |
| `static/js/app.js` | Tab routing, i18n, theme |
| `static/js/live-stats.js` | Dashboard, charts, intelligence |
| `static/js/search.js` | Search, edit, delete, history |
| `static/js/submit.js` | Single/bulk IOC submission UI |
| `static/js/champs.js` | Leaderboard, spotlight, ticker |
| `static/js/feed-pulse.js` | Feed health, anomalies, exclusions |
| `static/js/yara.js` | YARA management |
| `static/js/campaigns.js` | Campaign graph (vis.js) |
| `static/js/playbook.js` / `playbook-edit.js` | Playbook view and site management |
| `static/js/reports.js` | Intelligence reports (period picker, charts, PDF export) |
| `static/js/profile.js` | User profile and avatar |

Vendor libraries (all local, no CDN): Tailwind, Chart.js, vis.js, marked, turndown, Prism, html2canvas, jsPDF.

### Templates

```
templates/
  index.html          Main SPA (Commander Edition)
  login.html          Login page
  change_password.html  Forced password change
  profile.html        User profile (display name, avatar, role, email)
  base_app.html       (if used)
  admin/
    base.html         Admin layout
    users.html        User management
    settings.html     System settings (Auth, LDAP, MISP, Syslog)
    allowlist.html    Allowlist editor
    certificate.html SSL/TLS certificate
    scoring.html      Champs scoring method
    403.html          Forbidden
```

---

## Offline Deployment

ThreatGate is designed for air-gapped environments:

- All CSS, JS, fonts, icons served locally (no CDN)
- GeoIP database stored locally (`data/GeoLite2-City.mmdb`)
- LDAP is optional; works with `local_only` auth mode
- MISP integration connects only to a local MISP instance on the same server
- No telemetry, analytics, or external API calls

### Building an Offline Package

```bash
# On a machine with internet:
./package_offline.sh

# Output: threatgate_installer.zip
# Contains: all code, templates, static assets, Python wheels, systemd units
```

### Installing on Air-Gapped Server

```bash
unzip threatgate_installer.zip -d threatgate_install
cd threatgate_install
sudo ./setup.sh --offline
```

Prerequisites on target server:
- Python 3.8+ with `python3-venv` package
- SQLite3
- systemd

---

## Troubleshooting

### Service won't start

```bash
journalctl -u threatgate -n 50 --no-pager
```

### Database locked

- Ensure only one instance is running
- Restart: `sudo systemctl restart threatgate`
- The app retries commits automatically (3 attempts with backoff)

### MISP sync not running

```bash
systemctl status threatgate-misp-sync.timer
journalctl -u threatgate-misp-sync -n 20 --no-pager
```

Check Admin > Settings > MISP: ensure Enabled = Yes, URL and API key configured.

### HTTP redirect not working

```bash
systemctl status threatgate-redirect
```

Ensure SSL certificates are uploaded via Admin > Certificate, then restart:
```bash
sudo systemctl restart threatgate threatgate-redirect
```

### Reset all data

```bash
sudo systemctl stop threatgate
cd /opt/threatgate
python reset_data.py --all --yes
sudo systemctl start threatgate
```

### Full reinstall

```bash
sudo ./uninstall.sh --backup   # Saves data to /opt/threatgate_backup_*
sudo ./setup.sh --offline      # Fresh install
```

---

## Version

**ThreatGate v2.0 Beta - Commander Edition**  
Single source of version: `constants.py` → `VERSION` (used in UI and docs).  
Last updated: **March 2026**
