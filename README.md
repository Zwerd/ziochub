# ZIoCHub v2.0 Beta - IOC & YARA Mgmt

ZIoCHub is a **modern IOC & YARA Management Platform** built for SOC operations. Analysts submit indicators, ZIoCHub stores them in a SQLite database, and security devices ingest **plain-text feeds** for enforcement. Designed for **air-gapped / offline** environments.

### Open Source Projects Used

ZIoCHub is built on the following open source projects:

| # | Project | Purpose |
|---|--------|---------|
| 1 | [Flask](https://flask.palletsprojects.com/) | Web framework |
| 2 | [Flask-Login](https://github.com/maxcountryman/flask-login) | User session & authentication |
| 3 | [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/) | ORM and database integration |
| 4 | [Werkzeug](https://werkzeug.palletsprojects.com/) | WSGI utilities |
| 5 | [SQLite](https://www.sqlite.org/) | Embedded database |
| 6 | [geoip2](https://github.com/maxmind/GeoIP2-python) / [MaxMind](https://www.maxmind.com/) | GeoIP lookups (optional) |
| 7 | [maxminddb](https://github.com/maxmind/MaxMind-DB-Reader-python) | MaxMind DB reader (optional, used with geoip2) |
| 8 | [ldap3](https://github.com/cannatag/ldap3) | LDAP/AD authentication (optional) |
| 9 | [PyMISP](https://github.com/MISP/PyMISP) | MISP API integration (optional) |
| 10 | [dxlclient](https://github.com/opendxl/opendxl-client-python) / [dxltieclient](https://github.com/opendxl/opendxl-tie-client-python) | McAfee DXL/TIE – ePO hash reputation (optional) |
| 11 | [Tailwind CSS](https://tailwindcss.com/) | UI styling (build step) |
| 12 | [Chart.js](https://www.chartjs.org/) | Charts and dashboards |
| 13 | [vis-network](https://visjs.org/) (vis.js) | Campaign & IOC graph visualization |
| 14 | [marked](https://github.com/markedjs/marked) | Markdown parsing (Reports, Playbook) |
| 15 | [turndown](https://github.com/domchristie/turndown) | HTML-to-Markdown conversion |
| 16 | [jsPDF](https://github.com/parallax/jsPDF) | PDF export (Reports) |
| 17 | [html2canvas](https://html2canvas.hertzen.com/) | Screenshot for PDF export |
| 18 | [Prism](https://prismjs.com/) | YARA syntax highlighting |
| 19 | [Flag Icons](https://github.com/lipis/flag-icons) | Country flags in UI |

---

## Features

- **Authentication & User Management**: Local accounts, optional LDAP/AD integration, admin roles, profile (display name, avatar), change password, optional "must change password" on first login
- **MISP Integration**: Automatic IOC pull from a local MISP instance with configurable intervals
- **Champs Analysis**: Analyst leaderboard, multiple scoring methods (Weighted, Flat, By Type, Campaign Focus, Time Decay, Quality, Goal-Based, Smart/Effort), streak bonuses, team goals, rank tracking, activity spotlight, news ticker
- **Feed Pulse**: Real-time incoming/outgoing IOC monitoring with anomaly detection and analyst exclusions
- **Campaign Management**: Visual graph (vis.js) of campaigns and associated IOCs
- **YARA Rule Management**: Upload, approval workflow, quality scoring (10-50 pts), campaign linking
- **Intelligence Reports**: Period-based reports (day/week/month) with KPIs, type distribution, feed health, analyst activity, export to PDF
- **Multi-vendor Feeds**: Standard, Palo Alto (EDL), Checkpoint (CSV) feed formats
- **TAXII 2.1 / STIX 2.1**: TAXII 2.1 server for STIX 2.1 threat intelligence; active IOCs exposed as a TAXII collection for clients (e.g. Cisco IronPort ESA)
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

- [Open Source Projects Used](#open-source-projects-used)
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
scp -r ZIoCHub/ user@server:/tmp/

# Install
cd /tmp/ZIoCHub
sudo ./setup.sh
```

### Option 2: Offline (Air-Gapped)

```bash
# On dev machine (with internet):
./package_offline.sh
# Transfer ziochub_installer.zip to server

# On target server:
unzip ziochub_installer.zip -d ziochub_install
cd ziochub_install
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
| **8443** | HTTPS | ZIoCHub | Main application (gunicorn + SSL) |
| **8080** | HTTP | Redirect | 301 redirect to HTTPS on 8443 |
| **5000** | HTTP | Dev only | Flask development server (`python app.py`) |

- If SSL certificates are configured (Admin > Certificate), port 8443 serves HTTPS automatically
- If no certificates exist, port 8443 serves plain HTTP
- The HTTP redirect server on port 8080 runs alongside the main service

---

## Systemd Services

| Unit | Type | Description |
|------|------|-------------|
| `ziochub.service` | Main | Gunicorn application server (port 8443) |
| `ziochub-redirect.service` | Main | HTTP-to-HTTPS redirect (port 8080) |
| `ziochub-cleaner.timer` | Timer | Expired IOC cleanup (daily) |
| `ziochub-backup.timer` | Timer | Database + SSL + YARA backup (daily) |
| `ziochub-misp-sync.timer` | Timer | MISP IOC pull (interval set by admin) |

```bash
# Common commands
sudo systemctl status ziochub
sudo systemctl restart ziochub
sudo journalctl -u ziochub -f
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

### TAXII 2.1 / STIX 2.1

ZIoCHub exposes active IOCs as a TAXII 2.1 server so TAXII clients (e.g. Cisco IronPort ESA) can pull STIX 2.1 indicators.

| Endpoint | Description |
|----------|-------------|
| `GET /taxii2/` | TAXII 2.1 Discovery (server info, API roots) |
| `GET /taxii2/ziochub/` | API Root (collections list) |
| `GET /taxii2/ziochub/collections/` | Collections (single collection: `indicators`) |
| `GET /taxii2/ziochub/collections/indicators/` | Collection metadata |
| `GET /taxii2/ziochub/collections/indicators/objects/` | STIX 2.1 objects (paginated) |
| `GET /taxii2/ziochub/collections/indicators/objects/<id>/` | Single STIX object |
| `GET /taxii2/ziochub/collections/indicators/manifests/` | Manifests (paginated) |
| `GET /taxii2/ziochub/collections/indicators/objects/<id>/versions/` | Object versions |

Requests must include `Accept: application/taxii+json;version=2.1`. Only **active (non-expired) IOCs** are included.

---

All plain-text and YARA feeds return only **active (non-expired) IOCs**. Content-Type: `text/plain`.

---

## MISP Integration

ZIoCHub can pull IOC attributes from a local MISP instance automatically.

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

| MISP Type | ZIoCHub Type |
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

SQLite database: `data/ziochub.db`

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
| `FLASK_ENV` | — | Set to `production` in production; used with DEV_MODE for startup security warning |
| `ZIOCHUB_ENV` | — | Alternative to FLASK_ENV; set to `production` in production |
| `DEV_MODE` | `0` | Do not enable in production (dev auto-login, LDAP mock). App logs warning when on, and error when on with production env |
| `SECRET_KEY` | random | Flask secret key (set in production) |
| `ZIOCHUB_DATA_DIR` | `<app>/data` | Data directory override |
| `ZIOCHUB_MAX_CONTENT_MB` | `16` | Max upload size |
| `ADMIN_DEFAULT_PASSWORD` | `admin` | Initial admin password |
| `ZIOCHUB_PORT` | `8443` | Production gunicorn port |
| `ZIOCHUB_WORKERS` | `3` | Gunicorn worker count |
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

Automated via `ziochub-backup.timer` (daily). Backs up:
- `ziochub.db` (database)
- `data/ssl/*.pem` (SSL certificates)
- `data/YARA/*.yar` (YARA rules)
- `data/allowlist.txt`

Retention: 30 days. Manual run:
```bash
sudo -u ziochub /opt/ziochub/backup_ziochub.sh
```

### Expired IOC Cleanup

Automated via `ziochub-cleaner.timer`. Removes expired IOCs and logs each deletion to `ioc_history` with `event_type='expired'`.

### Data Reset

```bash
cd /opt/ziochub
sudo systemctl stop ziochub

# Interactive (asks per category)
python reset_data.py

# Full wipe (IOCs, YARA, campaigns, history, champs, sessions, MISP settings, users)
python reset_data.py --all --yes

# Selective
python reset_data.py --iocs --yara --history --yes
python reset_data.py --settings   # Reset MISP settings only

sudo systemctl start ziochub
```

### Lab User Setup

```bash
# Development (app on port 5000): run from project root, or use --env dev
python create_lab_users.py
python create_lab_users.py --env dev

# Production (app on port 8443): use --env prod (reads /opt/ziochub/users/users.json)
cd /opt/ziochub
sudo -u ziochub /opt/ziochub/venv/bin/python create_lab_users.py --env prod
# Or with password non-interactive:
sudo -u ziochub /opt/ziochub/venv/bin/python create_lab_users.py --env prod --password 'YourPassword'
```

Prompts for a common password (or use `--password`) and creates/updates users from `users/users.json`. For production, ensure `users/users.json` exists under `/opt/ziochub/users/` (copy from dev or create there).

### Reset Admin (or Any User) Password

If an admin or user is locked out or the password is forgotten, use the script under `scripts/` (installed with the app):

```bash
cd /opt/ziochub
sudo -u ziochub python scripts/reset_admin_password.py --username admin --password 'NewSecurePassword'
# Optional: set source to local so the user can log in with the new password
sudo -u ziochub python scripts/reset_admin_password.py --username admin --password 'NewSecurePassword' --source local
```

---

## Admin Scripts

When using a full deployment package (e.g. offline installer), the following scripts may be provided:

| Script | Description |
|--------|-------------|
| `setup.sh` | Production installer (online/offline/upgrade) |
| `uninstall.sh` | Full removal (services, files, user) |
| `package_offline.sh` | Build offline installer ZIP |
| `backup_ziochub.sh` | Manual backup (DB, SSL, YARA, allowlist) |
| `reset_data.py` | Wipe operational data (granular or full) |
| `create_lab_users.py` | Create lab analyst accounts |
| `cleaner.py` | Remove expired IOCs (runs via systemd timer) |
| `misp_sync_job.py` | MISP sync job (runs via systemd timer) |
| `http_redirect.py` | HTTP-to-HTTPS redirect server |
| `start.sh` | Gunicorn launcher with auto SSL detection |

**Scripts in `scripts/`** (installed under `/opt/ziochub/scripts/`):

| Script | Description |
|--------|-------------|
| `scripts/reset_admin_password.py` | Reset any user's password and optionally set `source=local` (e.g. after LDAP lockout) |

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
- **Feed Endpoints**: Public (no auth). Includes plain-text feeds and TAXII 2.1; restrict access via firewall rules
- **Offline**: No external network calls. All assets local
- **DEV_MODE**: Must not be enabled in production (enables dev auto-login and LDAP mock). In production set `DEV_MODE=0` or unset; the app logs a startup warning when DEV_MODE is on, and an error when both DEV_MODE and production environment (`FLASK_ENV=production` or `ZIOCHUB_ENV=production`) are detected.

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
  feeds.py          Feed generation (standard, PA, CP, YARA; STIX helpers)
  ioc.py            IOC submit (single/bulk) API
  reports.py        Intelligence reports (period-based stats, PDF export)
  search.py         Search, edit, delete, history API
  stats.py          Live stats counts, geo/TLD/email intelligence
  taxii_server.py   TAXII 2.1 server (STIX 2.1 indicators collection)
  yara.py           YARA rule management API

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
  index.html          Main SPA (IOC & YARA Mgmt)
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

ZIoCHub is designed for air-gapped environments and is **100% offline**: no CDN, no external scripts, no external stylesheets.

### 100% Offline - No CDN

- **No `<script src="https://cdn.tailwindcss.com">` or any CDN.** Tailwind is loaded from `static/js/tailwind.min.js` (local).
- **All `<script>` and `<link>` tags** use `url_for('static', filename='...')` - everything is served from your server (e.g. `tailwind.min.js`, `chart.min.js`, `vis-network.min.js`, `marked.min.js`, `prism.min.js`, `style.css`, `flag-icons.min.css`, etc.).
- **i18n**: Translation JSON files are loaded from `static/i18n/` (e.g. `en.json`, `he.json`) via relative URLs.
- **Lazy-loaded tab scripts** (champs, search, yara, feed-pulse, campaigns, reports) are all under `static/js/` - no external URLs.
- **No `fetch()` or XHR to external domains** - only same-origin calls to `/api/...` and `/static/...`.
- **Hunter's Playbook** default entries contain URLs (e.g. VirusTotal, OTX) as link data only; the app does not fetch them. If the user clicks a link, the browser may try to open it (in air-gap, that will fail unless you have a proxy).
- **GeoIP** database is local: `data/GeoLite2-City.mmdb`.
- **LDAP** is optional; works with `local_only` auth.
- **MISP** integration talks only to a local MISP instance (same server / internal network).
- No telemetry, analytics, or external API calls.

### Building an Offline Package

```bash
# On a machine with internet:
./package_offline.sh

# Output: ziochub_installer.zip
# Contains: all code (app, utils/, routes/ incl. TAXII 2.1, scripts/), templates, static assets, Python wheels, systemd units
```

### Installing on Air-Gapped Server

```bash
unzip ziochub_installer.zip -d ziochub_install
cd ziochub_install
sudo ./setup.sh --offline
```

Prerequisites on target server:
- Python 3.8+ with `python3-venv` package
- SQLite3
- systemd

---

## Troubleshooting

### Where to find logs

| Where | What |
|-------|------|
| **systemd journal** | All app output (gunicorn, Flask, errors). Main place to debug. |
| **CEF audit file** | Optional audit events (logins, avatar upload, etc.). |

**Commands:**

```bash
# Last 100 lines (errors, tracebacks, access)
journalctl -u ziochub -n 100 --no-pager

# Follow live
journalctl -u ziochub -f

# Today only
journalctl -u ziochub --since today --no-pager
```

**Audit log (if enabled):** `/opt/ziochub/data/audit_cef.log` (48-hour rotation).

### Avatar upload / "Network error"

The UI shows **"Network error"** when the request to upload an avatar fails (e.g. server error, timeout, or no response). Check the **server** side:

1. **Logs** — See [Where to find logs](#where-to-find-logs) above. After a failed upload, run:
   ```bash
   journalctl -u ziochub -n 50 --no-pager
   ```
   Look for `api_profile_avatar_upload failed` or `api_admin_user_avatar_upload failed` and the Python traceback below.

2. **Permissions** — The app (user `ziochub`) must be able to write to `static/avatars/`:
   ```bash
   ls -la /opt/ziochub/static/avatars
   sudo chown -R ziochub:ziochub /opt/ziochub/static/avatars
   sudo chmod 755 /opt/ziochub/static/avatars
   ```

3. **File size** — Max upload is 16 MB by default (`MAX_CONTENT_LENGTH`). Very large images may be rejected with 413.

4. **Lab users’ avatars** — If you used `create_lab_users.py`, avatars are copied from `users/` only when image files exist there (e.g. `users/alice.jpg`). To add/update avatars after creation, either run the script again with images in `users/`, or use the UI (Profile or Admin > Users) to upload; if the UI shows "Network error", use the logs and permissions steps above.

### Service won't start

```bash
journalctl -u ziochub -n 50 --no-pager
```

### Database locked

- Ensure only one instance is running
- Restart: `sudo systemctl restart ziochub`
- The app retries commits automatically (3 attempts with backoff)

### MISP sync not running

```bash
systemctl status ziochub-misp-sync.timer
journalctl -u ziochub-misp-sync -n 20 --no-pager
```

Check Admin > Settings > MISP: ensure Enabled = Yes, URL and API key configured.

### HTTP redirect not working

```bash
systemctl status ziochub-redirect
```

Ensure SSL certificates are uploaded via Admin > Certificate, then restart:
```bash
sudo systemctl restart ziochub ziochub-redirect
```

### Reset all data

```bash
sudo systemctl stop ziochub
cd /opt/ziochub
python reset_data.py --all --yes
sudo systemctl start ziochub
```

### Full reinstall

```bash
sudo ./uninstall.sh --backup   # Saves data to /opt/ziochub_backup_*
sudo ./setup.sh --offline      # Fresh install
```

---

## Version

**ZIoCHub v2.0 Beta - IOC & YARA Mgmt**  
Single source of version: `constants.py` → `VERSION` (used in UI and docs).  
Last updated: **March 2026**
