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
- [מודל נתונים (SQLite) והיסטוריה](#he-data)
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

- MISP: `utils/misp_sync.py` + `misp_sync_job.py` + timer.
- LDAP/AD: `utils/ldap_auth.py` + health/test endpoints.
- Cisco ESA: `utils/cisco_esa.py` + admin test endpoint.
- DXL/TIE: `utils/dxl_tie.py` (תלוי חבילות).
- GeoIP: `data/GeoLite2-City.mmdb`.
- Audit (CEF/Syslog): `utils/cef_logger.py`.

-

<a id="he-admin"></a>

## Admin: הגדרות, משתמשים, תעודות, Allowlist, Inbox

Admin UI: `templates/admin/*`  
Admin API: `routes/admin.py`

כולל:

- Settings (feature flags, sanity policy, feeds public)
- Users
- Integrations tests
- Allowlist management
- Certificate management
- Admin Inbox (`GET /api/admin/inbox`)

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

## מודל נתונים (SQLite) והיסטוריה

SQLite + SQLAlchemy:

- `models.py`
- `extensions.py`

דגש: `ioc_history` ו־`ioc_notes` נועדו לשמור context לאורך זמן (audit + knowledge).

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

### Production

`setup.sh` מתקין ומגדיר systemd.

### Offline

ראו `OFFLINE.md` + `package_offline.sh` + `setup.sh --offline`.

-

<a id="he-ops"></a>

## תפעול ותחזוקה (systemd, timers, backup, cleaner)

Timers נפוצים:

- `ziochub-cleaner.timer`
- `ziochub-backup.timer`
- `ziochub-misp-sync.timer`

סקריפטים:

- `backup_ziochub.sh`
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

- DB locked (SQLite): בדרך כלל תהליך כפול / פעולה מקבילית.
- YARA validate נכשל: `yara-python` לא מותקן ב־venv הנכון.
- GitHub Pages נשבר: משתמשים בנתיבים מוחלטים במקום יחסיים.

-

<a id="he-oss"></a>

## קוד פתוח — קרדיטים

ZIoCHub נשענת על פרויקטים כגון Flask, SQLAlchemy, Tailwind, Chart.js, vis-network, Prism, marked, Turndown, jsPDF, html2canvas ועוד.  
רשימה מלאה: [`../../README.md`](../../README.md)

