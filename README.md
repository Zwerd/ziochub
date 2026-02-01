# ThreatGate v3.2 — Commander Edition

ThreatGate is a **file-backed IOC Submission & Distribution Portal** built for SOC operations: analysts submit indicators, ThreatGate writes them to flat text files with strict formatting, and security devices ingest **plain-text feeds** (IOC-only) for enforcement.

This release is the **v3.2 Commander Edition**: a modern **cyber-glass** workstation with a clean separation between **Threat Intelligence** and **Analyst Performance**.

---

## What’s new in the current state

- **Modern Glass UI (Glassmorphism)**: translucent cards, subtle blur, neon accents.
- **Light/Dark Mode**:
  - **Dark**: neon commander styling (green/cyan accents).
  - **Light**: clean corporate styling (dark text, solid blue active-tab underline).
- **Refactored Dashboard Logic (Separation of Concerns)**:
  - **Live Stats (default tab)** = **Threat Intelligence** (3 HTML leaderboards; **no charts**).
  - **Champs Analysis** = **Analyst Performance** (Chart.js charts + analyst leaderboard).

---

## UI walkthrough (updated tab order)

1. **Live Stats** (Intel dashboard — default)
2. **Search & Investigate**
3. **Single Submission**
4. **Bulk CSV**
5. **Bulk TXT**
6. **YARA Upload**
7. **Champs Analysis** (Team Performance)

---

## Screenshots (placeholders)

Add screenshots under `docs/images/` (folder exists with `.gitkeep`).

### Live Stats — 3-Column Intelligence View (default)

![Live Stats — 3-Column Intelligence View](docs/images/live_stats_intel_3col.png)

> **Instruction:** Capture the **Live Stats** tab showing:
> - Sticky summary cards (Active IPs / Domains / Hashes)
> - **3-column intelligence view**:
>   - **Top Countries** leaderboard (flag + **country code** + progress bars)
>   - **Top TLDs** leaderboard (globe + `.tld` labels + progress bars)
>   - **Top Email Domains** leaderboard (envelope + `domain.tld` labels + progress bars)
> - “Live Updating…” indicator (when active)

### Search & Investigate

![Search & Investigate](docs/images/search_investigate.png)

> **Instruction:** Capture the **Search & Investigate** tab showing:
> - Search field + filter dropdown (`All`, `IOC Value`, `Ticket ID`, `User`, `Date`)
> - Results table with Expiration badges + Actions (Edit/Delete)

### Single Submission

![Single Submission](docs/images/single_submission.png)

> **Instruction:** Capture the **Single Submission** tab showing:
> - IOC Value, Type, Comment, Analyst, Ticket ID, TTL
> - A success toast if possible

### Champs Analysis — Team Performance

![Champs Analysis — Team Performance](docs/images/champs_analysis_team_performance.png)

> **Instruction:** Capture the **Champs Analysis** tab showing:
> - **Threat Velocity** (line chart)
> - **Analyst Activity** (pie/doughnut chart)
> - Analyst leaderboard with 🥇🥈🥉 for top 3

---

## Dashboards (v3.2 separation of concerns)

### Live Stats (Threat Intelligence) — no charts

Live Stats is dedicated to **Threat Intelligence** and renders 3 **HTML-based leaderboards** (uniform progress-bar design):

- **Top Countries** (IPs only)
  - Offline flags via local `flag-icons`
  - Shows **flag + country code** (e.g., `US`, `IL`)
- **Top TLDs** (Domains)
  - Extracts `.tld` from domain IOCs and ranks top 10
- **Top Email Domains** (Emails)
  - Extracts domain after `@` and ranks top 10

### Champs Analysis (Analyst Performance)

Champs Analysis is the **Team Performance** area:

- **Threat Velocity**: IOCs per day (Chart.js line chart)
- **Analyst Activity**: contributions by user (Chart.js pie/doughnut)
- **Analyst leaderboard**: ranked totals with medals 🥇🥈🥉

---

## Data model (flat files, strict format)

ThreatGate stores IOCs in `data/Main/`:

- `ip.txt`
- `domain.txt`
- `hash.txt`
- `email.txt`
- `url.txt`

### On-disk line format (don’t break this)

Each entry is a single line:

```
VALUE # Date:{ISO-8601} | User:{username} | Ref:{ticket_id} | Comment:{comment} | EXP:{YYYY-MM-DD or NEVER}
```

- **Thread safety**: writes are file-locked (`portalocker`).
- **Comments** are sanitized to prevent newline injection.

---

## Security integrations (Clean Feed API)

Security devices ingest **IOC-only** lists via plain text.

| Endpoint | Method | Output | Content-Type |
|---|---:|---|---|
| `/feed/ip` | GET | IPs | `text/plain` |
| `/feed/domain` | GET | Domains | `text/plain` |
| `/feed/hash` | GET | Hashes | `text/plain` |
| `/feed/email` | GET | Emails | `text/plain` |
| `/feed/url` | GET | URLs | `text/plain` |

Example response:

```
1.2.3.4
bad-domain.tld
evil@phish.tld
```

### Palo Alto (EDL) quick setup

- **Type**: IP Address List / Domain List (per endpoint)
- **Source**: `https://<threatgate-host>/feed/ip`
- **Refresh**: 5 minutes (recommended)

### Fortinet quick setup

- **Threat Feed URL**: `https://<threatgate-host>/feed/domain`
- **Update**: 5 minutes

### Generic consumer (curl + ipset)

```bash
curl -s "https://<threatgate-host>/feed/ip" | while read -r ip; do
  ipset add threatgate_ips "$ip" 2>/dev/null || true
done
```

---

## Installation

### Prereqs

- Python 3.8+

### Run locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

### Production

**Linux (Gunicorn):**

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

**Windows (Waitress):**

```bash
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

---

## Maintenance (TTL cleanup)

`cleaner.py` removes expired IOCs by parsing `EXP:` and deleting expired lines.

Cron (daily at 03:00):

```bash
0 3 * * * /usr/bin/python3 /path/to/ioc_submission/cleaner.py >> /var/log/threatgate-cleaner.log 2>&1
```

---

## Offline / air-gapped notes

- **Flags**: local `flag-icons` (offline, Windows-friendly SVG).
- **Charts**: local `static/js/chart.min.js` (used only in Champs Analysis).
- **GeoIP**: optional; system runs without it.
- UI uses Tailwind utility classes plus `static/css/style.css`. If you require **zero CDN usage**, vendor Tailwind locally.

---

## API (common endpoints)

| Endpoint | Method | Purpose |
|---|---:|---|
| `/api/submit-ioc` | POST | Single submission |
| `/api/search` | GET | Search (filterable) |
| `/api/edit` | POST | Edit comment/expiration |
| `/api/revoke` | POST | Delete IOC |
| `/api/recent` | GET | Live Feed sidebar |
| `/api/all-iocs` | GET | Stats + dashboards |
| `/api/analyst-stats` | GET | Champs leaderboard |
| `/api/v1/ioc` | POST | External ingestion (automation) |

---

## Version

**ThreatGate v3.2 — Commander Edition**  
Last updated: **January 2026**

