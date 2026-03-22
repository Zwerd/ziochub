# ZIoCHub vs MISP: Main Differences and ZIoCHub Advantages

This document summarizes the key differences between **ZIoCHub** and **MISP** (Malware Information Sharing Platform) and highlights where ZIoCHub offers distinct advantages for SOC operations.

---

## 1. Executive Summary

| Aspect | ZIoCHub | MISP |
|--------|---------|------|
| **Primary focus** | SOC daily operations: submit, validate, feed, score analysts | Threat intelligence: events, sharing, correlation, standards |
| **Complexity** | Lightweight, single app, SQLite, minimal ops | Full-featured TI platform, more components and tuning |
| **Deployment** | One server, optional air-gapped, no external deps | Often multi-instance, sharing networks, integrations |
| **Analyst engagement** | Built-in gamification (Champs), spotlight, reports | Not focused on analyst motivation/leaderboards |
| **Feed output** | Plain-text feeds (multi-vendor), simple URLs | Feeds and APIs, more formats and taxonomies |

**ZIoCHub can pull IOCs from MISP** (optional integration). The two can coexist: MISP for TI lifecycle and sharing, ZIoCHub for operational ingestion, validation, and analyst workflow.

---

## 2. Positioning

### ZIoCHub

- **IOC & YARA management platform for SOC teams.**
- Built for: daily submission, validation, TTL, campaigns, YARA rules, and **consumption by security devices** via simple feeds.
- Optimized for: speed of deployment, offline/air-gapped use, and **analyst visibility** (who submitted what, streaks, rankings).

### MISP

- **Threat intelligence sharing and event management.**
- Built for: modeling events, attributes, objects, taxonomies, and **sharing** between organizations.
- Optimized for: correlation, standards (STIX, TAXII, etc.), and large-scale TI workflows.

---

## 3. Main Differences

### 3.1 Architecture and Deployment

| ZIoCHub | MISP |
|---------|------|
| Single Flask app, SQLite, optional LDAP/MISP/Syslog | Rich stack, MySQL/MariaDB/PostgreSQL, many optional modules |
| Minimal dependencies; 100% offline capable | More moving parts; often used in connected TI communities |
| Quick install (e.g. one script), low maintenance | Deeper setup and tuning for large instances |

### 3.2 Data Model

| ZIoCHub | MISP |
|---------|------|
| **Flat IOC list** per type (IP, Domain, URL, Email, Hash) with metadata (analyst, TTL, campaign, notes) | **Event-centric**: events contain attributes, objects, galaxies, taxonomies |
| **Campaign** = named group of IOCs + graph visualization | **Event** = container for many attribute types and relationships |
| Optimized for “list of bad things to block” and feeds | Optimized for “threat story” and sharing/correlation |

### 3.3 Primary Users and Workflow

| ZIoCHub | MISP |
|---------|------|
| **SOC analysts** submitting and curating IOCs; managers viewing reports and leaderboards | **TI analysts and sharing communities** building events, tagging, and exporting to consumers |
| Submit → validate → TTL → campaign → feed; optional pull from MISP | Create event → add attributes/objects → tag → publish/share |

### 3.4 Analyst-Centric Features

| ZIoCHub | MISP |
|---------|------|
| **Champs Analysis**: leaderboard, scoring methods, streaks, team goals, badges, spotlight | No built-in analyst gamification or leaderboards |
| **Intelligence Reports**: period reports, KPIs, analyst spotlight, PDF export | Reporting more event/attribute oriented |
| **Feed Pulse**: who added what, anomaly hints, analyst context | Focus on event/attribute lifecycle, not “who added” as a first-class concept |
| Optional **exclusion of MISP sync user** from Champs and reports | N/A |

### 3.5 Feeds and Consumption

| ZIoCHub | MISP |
|---------|------|
| **Plain-text feeds** (standard, Palo Alto EDL, Checkpoint CSV, etc.) over HTTP | Multiple feed/API mechanisms; more formats and taxonomies |
| Direct “list of values” for firewalls, EDR, etc. | Often used as source that other systems (e.g. ZIoCHub) pull from and then serve to devices |

### 3.6 Validation and Safety

| ZIoCHub | MISP |
|---------|------|
| **Strict validation** per type (regex); allowlist; sanity checks (e.g. private IPs, short domains) | Flexible attribute model; validation depends on type and instance config |
| **TTL** and expiration; automatic handling of expired IOCs | Expiration and lifecycle configurable but not the core focus |

---

## 4. Where ZIoCHub Has Advantages Over MISP

### 4.1 Operational Simplicity

- **Faster to deploy and run**: one app, one DB, minimal ops.
- **Clear “submit → feed” path**: analysts add IOCs, devices hit feed URLs and get plain text.
- **No need to model events or taxonomies** if the goal is “maintain blocklists and serve them to our gear.”

### 4.2 Analyst Engagement and Visibility

- **Champs**: leaderboard, multiple scoring methods, streaks, team goals, badges — encourages participation and makes contribution visible.
- **Analyst Spotlight** in reports and in-app: who is active, top contributors, trends.
- **MISP Sync user** can be excluded from Champs and spotlight so automated import doesn’t distort rankings.

### 4.3 Offline and Restricted Environments

- **Designed for air-gapped / offline**: no mandatory external calls; all assets local.
- **Optional LDAP**: auth from existing AD/LDAP without exposing the platform to the internet.
- **Optional MISP pull**: one-way sync from MISP when connectivity exists, without requiring MISP to “push” into the SOC network.

### 4.4 Feed-Oriented and Device-Ready

- **Multi-vendor feed formats** out of the box (e.g. EDL, CSV) for common security products.
- **Simple URLs**; devices do HTTP GET and get a list; no API key or complex query model required for basic use.
- **Allowlist and sanity checks** reduce risk of blocking critical infrastructure.

### 4.5 YARA and Campaign in One Place

- **YARA rule management** with approval workflow, quality scoring, and campaign linking.
- **Campaign graph** (vis.js) for IOCs and campaigns in a single UI.
- **IOC notes** and **IOC history** (create/delete/expire) for traceability without event model.

### 4.6 Reporting and Management

- **Intelligence Reports**: day/week/month views, KPIs, analyst activity, feed health, export to PDF.
- **Admin**: users, LDAP, MISP sync, allowlist, certificates, syslog/CEF, in one settings surface.
- **Respects “exclude from Champs”** in reports so MISP sync doesn’t appear in analyst spotlight when configured.

---

## 5. Where MISP Remains Stronger

- **Threat intelligence sharing** between organizations and communities.
- **Event-centric model** and rich taxonomies (e.g. MISP galaxies, objects).
- **Standards**: STIX, TAXII, and broader ecosystem integrations.
- **Scale and flexibility** for large TI teams and complex event lifecycles.
- **Maturity and community**: long-standing project, many integrations and use cases.

---

## 6. When to Use Which (and Together)

- **Use ZIoCHub** when:
  - You need a **simple, operational** IOC and YARA hub for the SOC.
  - You want **analyst scoring, leaderboards, and visibility** (Champs, reports).
  - You prefer **lightweight deployment**, **offline capability**, and **plain-text feeds** for devices.
  - You want to **consume** IOCs from MISP (or other sources) and then serve them internally.

- **Use MISP** when:
  - You need **TI sharing**, **event modeling**, and **taxonomies**.
  - You participate in **TI communities** or need **STIX/TAXII** and similar standards.
  - Your primary workflow is **event-centric** and correlation-focused.

- **Use both** when:
  - MISP is your TI backbone (events, sharing, correlation).
  - ZIoCHub is your **operational layer**: pull from MISP (and/or manual input), validate, apply TTL/allowlist, and serve **feeds to security devices** while giving analysts a single place for submission, Champs, and reports.

---

## 7. Summary Table: ZIoCHub Advantages Over MISP

| Area | ZIoCHub advantage |
|------|-------------------|
| Deployment & ops | Lighter stack, SQLite, one app, offline-first |
| Analyst engagement | Champs, leaderboard, badges, team goals, spotlight |
| Feed delivery | Simple plain-text, multi-vendor formats, device-ready URLs |
| Validation & safety | Strict per-type validation, allowlist, sanity checks |
| Reporting | Period reports, analyst spotlight, PDF export; respects “exclude MISP” |
| YARA & campaigns | YARA workflow + campaign graph in same platform |
| Use case fit | SOC daily operations and blocklist curation vs. TI sharing and events |

This document reflects ZIoCHub as of the current codebase (e.g. MISP integration, Champs, Intelligence Reports, exclude-from-Champs behavior). For the latest feature set, refer to the project README and release notes.
