# ZIoCHub — פורטל ניהול IOC ו‑YARA (מדריך בעברית)

ברוך הבא למסמך שהתחיל כ־“בוא נרשום שני משפטים שלא נשכח איך זה עובד”, והסתיים כ־“יש מצב שזה יותר מסודר מהחיים שלנו”.  
ZIoCHub נולדה מתוך צורך אמיתי של SOC: **מקור אמת אחד** ל־IOC ול־YARA, עם הקשר (Campaigns), היסטוריה (History), פידים לציוד (Feeds), סטנדרטים לשיתוף מודיעין (TAXII/STIX), ויכולות תפעוליות שעוזרות למערכת לשרוד גם ביום שיש *הרבה יותר מדי* Hashes.

המסמך הזה אמור להיות **מקצועי, ארוך ומקיף**, אבל גם כזה שמפיח חיים: למה בחרנו ארכיטקטורה מסוימת, איפה היו “פינות כאב” של צוות אנליסטים, ואיך פתרנו אותן בלי להוסיף עוד מערכת שמישהו צריך לתחזק בחצי עין.

מילים מקצועיות באנגלית יופיעו איפה שהן עושות סדר: API, TTL, Sanity Checks, Allowlist, Audit, Offline, Static hosting, Demo.

קישורים חשובים:

- README באנגלית (מלא + עוד פרטי API): [`../../README.md`](../../README.md)
- פריסה אופליין: [`../../OFFLINE.md`](../../OFFLINE.md)
- YARA pending בפידים (למה זה עובד ככה): [`../YARA_FEEDS_AND_PENDING.md`](../YARA_FEEDS_AND_PENDING.md)
- Troubleshooting (מסמך ממוקד): [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md)
- DXL/TIE (אינטגרציה): [`../DXL_INTEGRATION.md`](../DXL_INTEGRATION.md)

מספר הגרסה שמופיע בממשק מגיע מ־`constants.py` (למשל **2.0 Beta**).

### עדכונים אחרונים (2026)

- **PostgreSQL (Production):** בסביבת production המערכת רצה על **PostgreSQL**; פרטי חיבור ב‑`data/ziochub.env`. SQLite (`data/ziochub.db`) משמש רק עד סיום מיגרציה בשדרוג, או לפיתוח מקומי עם `ZIOCHUB_ALLOW_SQLITE_DEV=true`. פירוט: [Database & migration](../../README.md#database--migration).
- **חבילות התקנה נפרדות:** `package_offline.sh` — אפליקציה + wheels בלבד. PostgreSQL **לא** בתוך ZIP האפליקציה. **Production:** IT מתקין PG → `setup.sh --offline --use-existing-postgresql`. **Lab:** `sudo ./package_postgresql_debs.sh` → ZIP נפרד, לחלץ לאותה תיקייה. ראו [Installation](../../README.md#installation).
- **Google SecOps (Chronicle):** דחיפת IOC ל‑**Data Table** ו/או **Reference Lists** (`v2/lists`); מיפוי גמיש IOC type → שם רשימה; הוספה בהגשה והסרה ב‑revoke/expire. ראו [Google SecOps push](../../README.md#google-secops-chronicle-push).
- **Integrations Hub** — **Admin → Integrations**: Import ↓ (MISP, **AdversaryGraph**, TAXII pull) · Export ↑ (פידים + TAXII server) · Push ↑ (Cortex, Google SecOps, Netskope, ESA, Trellix, MISP push, DXL, HTTP).
- **AdversaryGraph** — משיכת IOC מ‑IOC Library + YARA מ‑Detection Studio; משתמש סנכרון `adversarygraph_sync`; Feed Pulse → Pull State.
- מסמך Troubleshooting מעודכן: [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) (PostgreSQL, מיגרציה, אינטגרציות).

-

## תוכן עניינים

- [למה בכלל זה קיים](#he-why)
- [גלריית תמונות](#he-gallery)
- [מבט‑על: מה המערכת יודעת לעשות](#he-overview)
- [מודולי הממשק (טאבים) — פירוט](#he-tabs)
- [זרימת עבודה “יום בחיי אנליסט”](#he-day)
- [פידים (Feeds) — למה זה ציבורי ואיך משתמשים](#he-feeds)
- [TAXII 2.1 / STIX 2.1](#he-taxii)
- [אינטגרציות (אופציונלי)](#he-integrations)
- [Admin: הגדרות, משתמשים, תעודות, Allowlist, Inbox](#he-admin)
- [Sanity Checks + Allowlist — מנגנוני בטיחות](#he-safety)
- [Champs / Achievements / Ambition — מוטיבציה בצורה מבוקרת](#he-champs)
- [מודל נתונים (PostgreSQL) והיסטוריה](#he-data)
- [אבטחה (Security)](#he-security)
- [התקנה והרצה (Dev/Prod/Offline)](#he-install)
- [תפעול ותחזוקה (systemd, timers, backup, cleaner)](#he-ops)
- [DEMO סטטי (GitHub Pages)](#he-demo)
- [ארכיטקטורת קוד — איפה כל דבר חי](#he-architecture)
- [פתרון תקלות נפוצות](#he-troubleshooting)
- [קוד פתוח — קרדיטים](#he-oss)

-

<a id="he-why"></a>

## למה בכלל זה קיים

בוא נודה באמת: SOC זה לא “פרויקט חמוד”. זה פס ייצור של החלטות תחת לחץ. ומה שמפיל צוותים לא תמיד זו מתקפה — לפעמים זו פשוט העובדה שיש לנו **חמישה מקומות שונים** לאותו IOC.

התרחיש שכולנו מכירים:

- IOC מגיע ב־Email → מישהו מדביק ב־Chat.
- מישהו שומר ב־Excel “רק רגע”.
- מישהו אחר מוסיף ל־Firewall.
- אחרי שבוע: אין מושג מי הוסיף, למה, האם זה עדיין רלוונטי, מה ה־TTL, והאם זה קשור לקמפיין שכבר רץ אצלנו.

אז בנינו Hub אחד שמחזיק “את הסיפור המלא”:

- **IOC lifecycle**: create/edit/revoke/delete/expire עם היסטוריה.
- **TTL** אמיתי: “זמני” צריך להיעלם בזמן, אחרת הוא הופך ל־permanent bug.
- **Notes** שלא נעלמים עם האנליסט שיצא לחופשה.
- **Campaign context** + גרף קשרים (Graph) כדי להבין “מה קשור למה”.
- **YARA workflow** עם pending/approve כדי שלא נזריק חתימה שבורה לצרכנים.
- **Feeds** לציוד שמבין plain text בלי דיון תיאורטי.
- **TAXII/STIX** לצרכנים מודרניים.
- וכל זה בלי להכריח אותנו להיות תלויים בשירותי ענן (Offline‑friendly).

-

<a id="he-gallery"></a>

## גלריית תמונות

תמונות שמים תחת `docs/README_HE/images/` (יש שם `.gitkeep`).  
אם חסר לכם צילום מסך, זה הזמן “לתפוס רגע יפה” במערכת ולשמור אותו בשם עקבי.

שמות מומלצים:

- `01_overview_dashboard.png` — Live Stats
- `02_submit_iocs.png` — Submit IOCs
- `03_search_investigate.png` — Search & Investigate
- `04_feed_pulse.png` — Feed Pulse
- `05_yara_manager.png` — YARA Manager
- `06_champs.png` — Champs Analysis
- `07_campaign_graph.png` — Campaign Graph
- `08_reports.png` — Intelligence Reports
- `09_admin_integrations.png` — Admin Integrations
- `10_architecture_diagram.png` — Architecture diagram (אופציונלי)
- `11_admin_users.png` — Admin Users
- `12_admin_certificate.png` — Admin Certificate/SSL

![01 – Live Stats](docs/README_HE/images/01_overview_dashboard.png)
![02 – Submit](docs/README_HE/images/02_submit_iocs.png)
![03 – Search](docs/README_HE/images/03_search_investigate.png)
![04 – Feed Pulse](docs/README_HE/images/04_feed_pulse.png)
![05 – YARA](docs/README_HE/images/05_yara_manager.png)
![06 – Champs](docs/README_HE/images/06_champs.png)
![07 – Campaigns](docs/README_HE/images/07_campaign_graph.png)
![08 – Reports](docs/README_HE/images/08_reports.png)
![09 – Admin integrations](docs/README_HE/images/09_admin_integrations.png)
![10 – Architecture](docs/README_HE/images/10_architecture_diagram.png)
![11 – Admin users](docs/README_HE/images/11_admin_users.png)
![12 – Certificate](docs/README_HE/images/12_admin_certificate.png)

-

<a id="he-overview"></a>

## מבט‑על: מה המערכת יודעת לעשות

ZIoCHub היא שילוב של Portal + Data store + Feed server.

במילים פשוטות:

- יש UI שבו אנליסטים עובדים (SPA).
- יש API פנימי (JSON) שמשרת את ה־UI.
- יש endpoints ציבוריים של Feeds/TAXII שנועדו לצרכנים אחרים.
- יש שכבת Integrations (אופציונלית) שמחברת החוצה לפי צורך.

במילים של SOC:

- **Time‑to‑action**: להכניס IOC מהר, עם ולידציה, בלי להשאיר “אוברדראפט” של תקלות.
- **Auditability**: להבין מי עשה מה ומתי (History + Audit).
- **Governance**: pending ל־YARA, Sanity policy, Allowlist, Admin controls.
- **Distribution**: Feeds/TAXII לציוד.

-

<a id="he-tabs"></a>

## מודולי הממשק (טאבים) — פירוט

הממשק הראשי נמצא ב־`templates/index.html`. קבצי JS נמצאים תחת `static/js/`.  
`static/js/app.js` הוא ה־orchestrator: auth state, theme/language, modals, lazy loading, ועוד.

### Live Stats (Dashboard + Activity)

זה הדף של “מה המצב עכשיו”. הוא נותן KPI‑ים וויזואליזציה כדי לחוש חריגות לפני שהן הופכות לאירוע.

מה תמצאו שם:

- ספירות IOC פעילים לפי סוג (IP/Domain/URL/Hash/Email) + YARA.
- “Threat Intelligence Dashboard” עם Top Countries / TLDs / Email domains / Campaign impact.
- Live feed של פעילות.

קוד:

- `static/js/live-stats.js`
- API: `GET /api/stats`, `GET /api/stats/counts`

### Feed Pulse (Feed health + anomalies + telemetry)

Feed Pulse הוא המקום שבו אנחנו אומרים את מה שכולנו יודעים: “לא כל IOC צריך להיכנס, ולא כל IOC צריך להישאר”.

יכולות עיקריות:

- Incoming / Outgoing / Excluded לפי חלון זמן (Period).
- Sanity anomalies (defang, private IP, פורמטים בעייתיים וכו’).
- Exclusions: החרגות שמונעות “Spam” של אותה אנומליה.
- Allowlist read‑only: הצגה בטוחה של allowlist לצוות.
- Connections telemetry: מי משך `/feed/...` או `/taxii2/...` ומתי.

קוד:

- `static/js/feed-pulse.js`
- API: `GET /api/feed-pulse`, `POST/DELETE /api/sanity-exclude`, `GET /api/integration-connections`, `GET /api/allowlist-view`

### Search & Investigate (הבית של האנליסט)

פה עובדים בפועל: חיפוש, סינון, הקשר, והחלטות.

יכולות:

- חיפוש IOC עם פילטרים.
- Edit / Revoke / Delete.
- History: מי עשה מה ומתי.
- IOC Notes: הערות לפי (type+value) ששורדות גם מחיקות.
- Export CSV.

קוד:

- `static/js/search.js`
- API: `GET /api/search`, `GET /api/ioc-history`, `GET/POST /api/ioc-notes`, `GET /api/export`

### Submit IOCs (Single + Bulk + Staging)

במערכת אמיתית, הבעיה אינה “להוסיף IOC”. הבעיה היא להוסיף IOC **נכון**, בלי לשבור מדיניות ובלי להציף את הצוות בדופליקציות.

מה יש:

- Single IOC
- TXT upload
- Paste messy text
- CSV bulk
- Preview/Staging
- TTL/Expiration policies
- Tags + Campaign assignment

קוד:

- `static/js/submit.js`
- API: `POST /api/submit-ioc`, `POST /api/preview-*`, `POST /api/submit-staging`

### YARA Manager (Upload/Write/Status + Approval)

YARA היא חרב חדה. היא יכולה להציל, והיא יכולה גם לייצר FP/שבר תפעולי אם נשלח כלל שבור לצרכנים.

לכן יש workflow:

- Upload/Write
- Validate syntax (“Check syntax”)
- Pending approval → Approve/Reject
- Approved repository → feeds

קוד:

- `static/js/yara.js`
- API: `/api/upload-yara`, `/api/yara/pending`, `/api/yara/approve`, `/api/yara/reject`, `/api/yara/validate-syntax`
- הסבר pending feeds: `docs/YARA_FEEDS_AND_PENDING.md`

### Champs Analysis (Gamification עם גבולות)

Champs הוא לא “משחק”. הוא כלי ניהולי שמייצר accountability ומוטיבציה מבוקרת.

כולל:

- Leaderboard + Spotlight
- Team goals (weekly/monthly)
- Ticker messages (RTL/LTR)

קוד:

- `static/js/champs.js`
- API: `/api/champs/leaderboard`, `/api/champs/analyst/<user_id>`, `/api/champs/team-goal`, `/api/champs/ticker`

### Campaign Graph (Context graph)

Campaign Graph הופך “רשימת IOC” לסיפור.

כולל:

- CRUD לקמפיינים
- Link IOC/YARA לקמפיין
- Graph visualization (vis-network)
- Export (CSV/JSON)
- Reference image (אופציונלי)

קוד:

- `static/js/campaigns.js`
- API: `/api/campaigns`, `/api/campaigns/link`, `/api/campaign-graph/<id>`, `/api/campaigns/<id>/export(-json)`

### Hunter’s Playbook (Knowledge base)

תיעוד חקירה חי: קבוצות, אתרים, workflows, Markdown, ויכולת לערוך בצורה נוחה.

קוד:

- `static/js/playbook.js`, `static/js/playbook-edit.js`
- API: `/api/playbook`, `/api/playbook/reorder`

### Intelligence Reports (KPIs + PDF)

דוחות לפי Period (Day/Week/Month) עם KPIs וייצוא PDF.

קוד:

- `static/js/reports.js`
- API: `/api/reports/data`, `/api/reports/periods`
- PDF: html2canvas + jsPDF

-

<a id="he-day"></a>

## זרימת עבודה “יום בחיי אנליסט”

1. Live Stats → baseline + חריגות.
2. Feed Pulse → מה נכנס/יצא + anomalies + החלטות.
3. Submit IOCs → preview, TTL, tags, campaign.
4. Search & Investigate → notes/history/edit/revoke/delete/export.
5. Campaign Graph → קשרים/ייצוא.
6. YARA → validate → pending → approve.
7. Reports → PDF ל־stakeholders.

-

<a id="he-feeds"></a>

## פידים (Feeds) — למה זה ציבורי ואיך משתמשים

פידים מיועדים לצרכנים חיצוניים ולכן לרוב נשמרים ללא auth ברמת האפליקציה, ומוגנים ברמת הרשת (Firewall / reverse proxy / internal segment).

קוד: `routes/feeds.py` (prefix: `/feed`)

Endpoints עיקריים:

- Standard: `/feed/ip`, `/feed/domain`, `/feed/url`, `/feed/hash`, `/feed/md5`, `/feed/sha1`, `/feed/sha256`, `/feed/email`
- Palo Alto EDL: `/feed/pa/*` (כולל url בלי protocol)
- Check Point CSV: `/feed/cp/*`
- Cisco ESA: `/feed/esa/email`
- Trellix ePO: `/feed/epo/files-list`, `/feed/epo/<ticket_id>`
- STIX bundle: `/feed/stix`
- YARA: `/feed/yara-list`, `/feed/yara-content/<filename>`

הערה חשובה: YARA pending לא יוצא ב־feeds בכוונה. פירוט: `docs/YARA_FEEDS_AND_PENDING.md`.

-

<a id="he-taxii"></a>

## TAXII 2.1 / STIX 2.1

TAXII server נמצא ב־`routes/taxii_server.py` תחת `/taxii2/...`.

דוגמאות:

- `GET /taxii2/` (Discovery)
- `GET /taxii2/ziochub/collections/`

Header חובה ללקוחות:

- `Accept: application/taxii+json;version=2.1`

-

<a id="he-integrations"></a>

## אינטגרציות (אופציונלי)

הגדרה: **Admin → Integrations** (לא ב‑Settings).

### Import (משיכה — Pull)

| מקור | קוד | הערות |
|------|-----|--------|
| **MISP** | `utils/misp_sync.py`, `misp_sync_job.py`, `ziochub-misp-sync.timer` | PyMISP; IOC עם analyst `misp_sync` |
| **AdversaryGraph** | `utils/adversarygraph_sync.py`, scheduler ב‑app | FastAPI backend; IOC + YARA; analyst `adversarygraph_sync` |
| **TAXII 2.1 remote** | `utils/taxii_sync.py`, `ziochub-taxii-sync.timer` | משיכה משרת TAXII חיצוני |

Feed Pulse → **Pull State** מציג סטטוס MISP / AdversaryGraph / TAXII.

### Export & Push

- **Export**: פידים ציבוריים, cache, **TAXII server** (`routes/taxii_server.py`)
- **Push IOC**: Cortex XDR, Google SecOps, Netskope, Cisco ESA, HTTP, MISP push, OpenDXL
- **Push YARA**: Trellix EX/CMS/NX, HTTP YARA

**Google SecOps:** Data Table (אופציונלי) + Reference Lists (`v2/lists`, אופציונלי) — יעדים עצמאיים; מיפוי `[{"ioc_type":"IP","list_name":"..."}]`. פירוט: [Google SecOps](../../README.md#google-secops-chronicle-push).

### תשתית

- LDAP/AD: `utils/ldap_auth.py`
- Cisco ESA: `utils/cisco_esa.py`
- Google SecOps: `utils/google_secops.py`, `utils/google_secops_reference_lists.py`
- DXL/TIE: חבילות אופציונליות
- GeoIP: `data/GeoLite2-City.mmdb`
- Audit (CEF/Syslog): `utils/cef_logger.py`

פירוט מלא (כולל COMMENT mapping ל‑AdversaryGraph): [`../../README.md#inbound-integrations-pull`](../../README.md#inbound-integrations-pull)

-

<a id="he-admin"></a>

## Admin: הגדרות, משתמשים, תעודות, Allowlist, Inbox

Admin UI: `templates/admin/*`  
Admin API: `routes/admin.py`  
גישה: **`/admin`** (דורש admin)

| דף | נתיב | תפקיד |
|-----|------|--------|
| **Users** | `/admin/users` | משתמשים, LDAP/local, avatar, must-change-password; משתמשי מערכת (MISP/TAXII/AG) לא ניתנים לעריכה |
| **Settings** | `/admin/settings` | Search, Workflow, Tags, LDAP, Syslog |
| **Integrations** | `/admin/integrations` | Import / Export / Push — ראו [אינטגרציות](#he-integrations) |
| **Distribution** | `/admin/downstream` | רישום צרכני פיד (Feed Pulse Connections) |
| **Sanity Check** | `/admin/sanity` | כללי Feed Pulse anomalies |
| **Allowlist** | `/admin/allowlist` | `allowlist.txt` |
| **Certificate** | `/admin/certificate` | HTTPS cert/key |
| **Scoring** | `/admin/scoring` | שיטת ניקוד Champs |
| **Logs** | `/admin/logs` | צפייה ב‑CEF audit log |

**Admin Inbox** (באפליקציה הראשית): IOC / YARA / tag suggestions ממתינים — `GET /api/admin/inbox`.

מדריך מלא באנגלית: [`../../README.md#admin-panel-reference`](../../README.md#admin-panel-reference)

-

<a id="he-safety"></a>

## Sanity Checks + Allowlist — מנגנוני בטיחות

Sanity policy + allowlist הם ה־guardrails של המערכת:

- Block/Warn policy (admin)
- Exclusions (feed pulse)
- Hard‑block של ערכים מסוימים לפי allowlist

קוד:

- `utils/sanity_checks.py`
- `utils/allowlist.py`

-

<a id="he-champs"></a>

## Champs / Achievements / Ambition — מוטיבציה בצורה מבוקרת

הפיצ’רים האלה נועדו לשמור אנרגיה לאורך זמן, אבל הם גם ניתנים לכיבוי בפרופיל.

קוד:

- `static/js/app.js`, `static/js/champs.js`, `static/js/profile.js`
- API: `/api/profile`, `/api/ambition-message`

-

<a id="he-data"></a>

## מודל נתונים (PostgreSQL) והיסטוריה

**Production:** PostgreSQL — credentials ב‑`data/ziochub.env` (`ZIOCHUB_DATABASE_URL` או `ZIOCHUB_PG_*`).  
**Legacy / dev:** `data/ziochub.db` (SQLite) רק עד סיום מיגרציה בשדרוג, או לפיתוח מקומי עם `ZIOCHUB_ALLOW_SQLITE_DEV=true`.

| סביבה | מנוע | קובץ הגדרות | הערות |
|--------|------|-------------|--------|
| **Production** | **PostgreSQL** | `data/ziochub.env` | `setup.sh` + systemd |
| **שדרוג מ‑SQLite** | SQLite → PostgreSQL | `ziochub.db` + `ziochub.env` | `migrate_sqlite_to_postgres.py` |
| **Dev מקומי** | SQLite (אופציונלי) | `data/ziochub.db` | רק עם `ZIOCHUB_ALLOW_SQLITE_DEV=true` |

סדר קביעת חיבור (`utils/db_config.py`): משתני סביבה → `ziochub.env` → קובץ SQLite legacy → שגיאה.

SQLAlchemy:

- `models.py`
- `extensions.py`
- `utils/db_config.py`, `utils/schema_migrations.py`

דגש: `ioc_history` ו־`ioc_notes` נועדו לשמור context לאורך זמן (audit + knowledge).

טבלאות נוספות (2026): `downstream_systems`, `feed_source_last_seen`, `ioc_downstream_events`, `feed_cache_entries`, `user_notifications` — ראו [`../../README.md#data-model`](../../README.md#data-model).

-

<a id="he-security"></a>

## אבטחה (Security)

- Flask-Login session auth לרוב ה־UI/API
- Password hashing via Werkzeug (scrypt)
- Feeds/TAXII: הגנה ברשת
- Audit logging (CEF) + optional syslog

-

<a id="he-install"></a>

## התקנה והרצה (Dev/Prod/Offline)

### פיתוח

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

**ללא PostgreSQL (פיתוח בלבד):**

```bash
export ZIOCHUB_ALLOW_SQLITE_DEV=true   # Windows: set ZIOCHUB_ALLOW_SQLITE_DEV=true
python app.py
```

Production ו‑offline **דורשים PostgreSQL**.

### Production

`setup.sh` מתקין ומגדיר systemd — **לא** יוצרים venv ידנית תחת `/opt/ziochub`.

#### Python & venv (production)

| פריט | התקנה production | ב‑ZIP? |
|------|------------------|--------|
| `python3` על Linux | חובה — המפרש ש‑`setup.sh` משתמש בו | לא |
| `python3-venv` (חבילת OS) | חובה — בלי זה יצירת venv נכשלת | לא |
| `/opt/ziochub/venv` | **`setup.sh` יוצר אוטומטית** | לא |
| `packages/*.whl` | תלויות Python | כן |

**גרסת Python חייבת להתאים:** ה‑wheels (למשל `cp312`) נבנים עבור גרסת Python ספציפית. `setup.sh` מריץ `python3 -m venv` עם **`python3` של השרת**.

**כלל:** `./package_offline.sh` על build machine עם **אותה distro, ארכיטקטורה ו‑Python major.minor** כמו השרת.

```bash
# על השרת (לפני build):
python3 --version

# על מכונת build — אותה גרסה (למשל 3.12.x):
python3 --version
./package_offline.sh
```

**לפני `setup.sh` על השרת:**

```bash
sudo apt-get install -y python3 python3-venv
python3 -m venv /tmp/test && rm -rf /tmp/test   # אופציונלי — בדיקה
```

פירוט מלא: [Python & venv (production)](../../README.md#python--venv-production)

### Offline

ראו `OFFLINE.md` + `package_offline.sh` (אפליקציה) + **`package_postgresql_debs.sh`** (PostgreSQL — ZIP נפרד ל‑lab).

**Lab / air-gap — שני ZIPים, שתי תיקיות, installer אחד (`setup.sh` בלבד):**

```bash
mkdir -p ziochub_app ziochub_postgresql
python3 -m zipfile -e ziochub_*_installer.zip ziochub_app
python3 -m zipfile -e ziochub_postgresql_debs_*.zip ziochub_postgresql
cd ziochub_app && sudo ./setup.sh --offline \
  --postgresql-debs-dir ../ziochub_postgresql/postgresql-debs
```

ZIP של PostgreSQL **אינו** installer — רק `postgresql-debs/*.deb`.

**Production:** IT מתקין PostgreSQL → `sudo ./setup.sh --offline --use-existing-postgresql`

פירוט: [Lab / air-gap: PostgreSQL .deb via external Linux machine](../../README.md#lab--air-gap-postgresql-deb-via-external-linux-machine)

### שדרוג מ‑SQLite

```bash
sudo ./setup.sh --upgrade --offline
```

לוג מיגרציה: `data/migrate_sqlite_to_postgres.log`

-

<a id="he-ops"></a>

## תפעול ותחזוקה (systemd, timers, backup, cleaner)

Timers נפוצים:

- `ziochub-cleaner.timer` — מחיקת IOC שפג תוקף (+ ESA remove אם מופעל)
- `ziochub-backup.timer` — **pg_dump** + SSL + YARA + allowlist + audit log
- `ziochub-misp-sync.timer` — MISP pull
- `ziochub-taxii-sync.timer` — TAXII pull (אם מופעל)

סקריפטים:

- `backup_ziochub.sh` — גיבוי ידני (PostgreSQL + קבצים)
- `scripts/migrate_sqlite_to_postgres.py` — מיגרציה מ‑SQLite
- `cleaner.py`
- `reset_data.py`
- `scripts/reset_admin_password.py`

-

<a id="he-demo"></a>

## DEMO סטטי (GitHub Pages)

הדמו נבנה כדי לעבוד ב־static hosting תחת subpath (GitHub Pages).  
הבילדר:

- `demo/ziochub-demo/build_demo.py`

הפידים בדמו נבנים כעמודים סטטיים כדי שלא יהיה תלוי ב־JS mocking:

- `demo/ziochub-demo/site/feed/<type>/index.html`

והלינקים ב־Feed Catalog בדמו חייבים להיות יחסיים (למשל `./feed/ip/`) ולא מוחלטים (`/feed/ip`).

-

<a id="he-architecture"></a>

## ארכיטקטורת קוד — איפה כל דבר חי

Backend:

- `app.py`
- `routes/` (admin/auth/search/ioc/feeds/taxii_server/stats/campaigns/champs/yara/reports)

Frontend:

- `templates/index.html`
- `static/js/*`
- `static/css/style.css`
- `static/i18n/*`

-

<a id="he-troubleshooting"></a>

## פתרון תקלות נפוצות

מסמך מלא: [`../TROUBLESHOOTING.md`](../TROUBLESHOOTING.md)

| תקלה | כיוון |
|------|--------|
| PostgreSQL connection | `systemctl status postgresql`; בדיקת `data/ziochub.env` |
| מיגרציה נכשלה | `data/migrate_sqlite_to_postgres.log`; גיבוי `pre_pg_migration_*` |
| DB locked | **רק SQLite legacy** — תהליך כפול; שדרג ל‑PostgreSQL |
| MISP / AdversaryGraph / TAXII | Admin → Integrations → Import; Feed Pulse → Pull State |
| YARA validate נכשל | `yara-python` לא מותקן ב‑venv הנכון |
| GitHub Pages | נתיבים מוחלטים במקום יחסיים |

-

<a id="he-oss"></a>

## קוד פתוח — קרדיטים

ZIoCHub נשענת על פרויקטים כגון Flask, SQLAlchemy, Tailwind, Chart.js, vis-network, Prism, marked, Turndown, jsPDF, html2canvas ועוד.  
רשימה מלאה: [`../../README.md`](../../README.md)

