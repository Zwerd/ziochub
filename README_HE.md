# ZIoCHub — פורטל ניהול IOC ו‑YARA (בעברית)

זה ה־README בעברית. הוא לא “מסמך דרישות”, הוא יותר כמו יומן מלחמה של SOC: הייתה בעיה, נשבר לנו עוד משהו, ואז החלטנו שעדיף שיהיה לנו **Hub אחד** שמחזיק IOC + YARA + קמפיינים + דוחות + פידים — ובסוף גם מחייך אלינו בחזרה.

לגרסה האנגלית המלאה (כולל פרטים נוספים על API): [`../../README.md`](../../README.md)  
לפריסה אופליין: [`../../OFFLINE.md`](../../OFFLINE.md)  
לטיפול ב‑YARA pending בפידים: [`../YARA_FEEDS_AND_PENDING.md`](../YARA_FEEDS_AND_PENDING.md)

מספר הגרסה שמופיע בכותרת המערכת מגיע מ־`constants.py` (למשל **2.0 Beta**).

-

## תוכן עניינים

- [למה בכלל זה קיים](#he-why)
- [מה רואים בממשק (הטאבים)](#he-tabs)
- [זרימת עבודה “יום בחיי אנליסט”](#he-day)
- [פידים, TAXII, ומה פתאום צריך גם וגם](#he-feeds-taxii)
- [אינטגרציות (אופציונלי)](#he-integrations)
- [אדמין ומה הוא שולט](#he-admin)
- [מודל נתונים (SQLite)](#he-data)
- [אבטחה (בגובה העיניים)](#he-security)
- [התקנה והרצה](#he-install)
- [שירותים, טיימרים ותחזוקה](#he-ops)
- [DEMO סטטי (GitHub Pages)](#he-demo)
- [ארכיטקטורת קוד — איפה כל דבר חי](#he-architecture)
- [פתרון תקלות נפוצות](#he-troubleshooting)
- [קרדיטים וקוד פתוח](#he-oss)

-

<a id="he-why"></a>

## למה בכלל זה קיים

הסיפור הקצר: יום אחד גילינו שיש לנו חמישה מקומות שונים ל־IOC. אחד באקסל, אחד ב־MISP, אחד בפתקיות, אחד ב־SIEM, ואחד בראש של “רן מהלילה”.  
הסיפור הארוך: אחרי שהאקסל החליט שהוא “נעול לעריכה”, והפתקיות החליטו שהן “ננעלות בתוך הכיס של המכנסיים בכביסה”, החלטנו להפסיק להתווכח עם המציאות:

- צריך **מקור אמת אחד**.
- צריך שזה יעבוד גם כשהרשת עקומה / מנותקת / “ה‑FW עשה עדכון”.
- צריך שזה יהיה **פשוט**: אנליסט צריך IOC, קמפיין, הערה, תפוגה — לא דוקטורט.
- צריך פידים לציוד שמבין **plain-text**.
- ואם כבר יש לנו את כל זה, אז למה לא להפוך את העבודה לקצת יותר אנושית עם Champs, טיקר, יעדי צוות, ודוחות.

ZIoCHub בנויה סביב שלושה עקרונות:

- **OFFLINE‑friendly**: אפשר לעבוד בלי תלות בקריאות חיצוניות שוטפות. GeoIP יכול להיות מקומי (`data/GeoLite2-City.mmdb`). אינטגרציות הן “אם רוצים”.
- **KISS**: אפליקציה אחת, SQLite אחד, גיבוי = קובץ.
- **SOC‑first**: חקירה, הערות, היסטוריה, קמפיינים, YARA, פידים, TAXII — סביב הזרימה האמיתית של הצוות.

-

<a id="he-tabs"></a>

## מה רואים בממשק (הטאבים)

המערכת היא SPA (מסך אחד עם טאבים) ב־`templates/index.html`, והלוגיקה מפוצלת לקבצי JS תחת `static/js/`.

### Live Stats

מה זה נותן לנו?

- **ספירות** של IOC פעילים לפי סוג (IP/Domain/URL/Hash/Email) + YARA.
- **Dashboard של מודיעין**: Top Countries / TLD / Email Domains / Campaign Impact.
- **Live Feed** של פעילות אחרונה.

הקבצים הרלוונטיים:

- `static/js/live-stats.js`
- API: `GET /api/stats`, `GET /api/stats/counts`

### Feed Pulse

אם Live Stats זה “כמה יש לנו”, Feed Pulse זה “מה קרה לנו בזמן האחרון”.

- Incoming / Outgoing / Excluded (לפי חלון זמן)
- **Sanity anomalies**: דברים חשודים שמופיעים ב־IOC (למשל IP פנימי, דומיין קצר מדי, defang וכד’)
- **Allowlist**: כדי לא לשרוף לעצמנו תשתית קריטית
- **Connections**: מי משך פידים (`/feed/...`) או TAXII (`/taxii2/...`) ומתי
- Export report

הקבצים הרלוונטיים:

- `static/js/feed-pulse.js`
- API: `GET /api/feed-pulse`, `POST/DELETE /api/sanity-exclude`, `GET /api/integration-connections`, `GET /api/allowlist-view`

### Search & Investigate

זה המקום שבו אנליסטים חיים בפועל.

- חיפוש IOC עם פילטרים
- עריכה / revoke / delete
- **היסטוריה מלאה** (מי עשה מה ומתי)
- **IOC Notes**: הערות לפי (type+value) ששורדות גם מחיקות (כי לפעמים צריך לזכור “למה זה היה פה בכלל”)
- ייצוא CSV

הקבצים הרלוונטיים:

- `static/js/search.js`
- API: `GET /api/search`, `GET /api/ioc-history`, `GET/POST /api/ioc-notes`, `GET /api/export`

### Submit IOCs

ארבעה מצבים, כי החיים מגוונים:

- Single IOC
- TXT (קובץ)
- Paste (לוגים/דוחות מבולגנים)
- CSV (בולק)

כולל Preview/Staging כדי לא להכניס זבל בלחיצה אחת.

הקבצים הרלוונטיים:

- `static/js/submit.js`
- API: `POST /api/submit-ioc`, `POST /api/preview-*`, `POST /api/submit-staging`

### YARA Manager

שלושה מצבים:

- Upload (קובץ)
- Write (כתיבה בתוך המערכת)
- Status (מאושרים/ממתינים)

מה מיוחד כאן?

- “Check syntax” בצד שרת (עם `yara-python`) כדי לא לשלוח כלל שבור לכולם.
- Workflow של pending → approve/reject (מאוד בכוונה).

קבצים:

- `static/js/yara.js`
- API: `/api/upload-yara`, `/api/yara/pending`, `/api/yara/approve`, `/api/yara/reject`, `/api/yara/validate-syntax`

### Champs Analysis

המוטו: “אי אפשר לנצח את האויב כל היום בלי קצת ניקוד וניצנוץ”.

- Leaderboard + Analyst spotlight
- XP/Badges/Level
- יעדי צוות (שבועי/חודשי)
- טיקר הודעות (RTL/LTR)

קבצים:

- `static/js/champs.js`
- API: `/api/champs/leaderboard`, `/api/champs/analyst/<user_id>`, `/api/champs/team-goal`, `/api/champs/ticker`

### Campaign Graph

כשיש IOC בלי הקשר, זה סתם טקסט. כשמחברים אותם לקמפיין זה כבר “תמונה”.

- ניהול קמפיינים (CRUD)
- קישור IOC ו‑YARA לקמפיין
- גרף ויזואלי (vis-network)
- ייצוא (CSV/JSON)
- תמונת Reference (אופציונלי)

קבצים:

- `static/js/campaigns.js`
- API: `/api/campaigns`, `/api/campaigns/link`, `/api/campaign-graph/<id>`, `/api/campaigns/<id>/export(-json)`

### Hunter’s Playbook

מקום מרוכז לקישורים/Workflow של חקירה. כן, גם “האתר ההוא שכולם שומרים בבוקמרק אבל אף אחד לא זוכר”.

קבצים:

- `static/js/playbook.js`, `static/js/playbook-edit.js`
- API: `/api/playbook`, `/api/playbook/reorder`

### Intelligence Reports

דוחות תקופתיים (Day/Week/Month), KPIs, גרפים וייצוא PDF.

קבצים:

- `static/js/reports.js`
- API: `/api/reports/data`, `/api/reports/periods`
- PDF: `html2canvas` + `jsPDF`

-

<a id="he-day"></a>

## זרימת עבודה “יום בחיי אנליסט”

ב־08:00 אתה נכנס. ב־08:01 אתה כבר יודע שזה הולך להיות יום עם הרבה Hashes.

1. **Live Stats** נותן תמונת מצב: האם יש “עלייה מוזרה” ב‑Domains? האם יש Top Country שמופיע יותר מדי?
2. עוברים ל־**Feed Pulse** כדי להבין מה חדש באמת: נכנס/יצא/חריגים, ואם יש “סימני שפיות” שנכשלו (כי לפעמים האויב שולח לנו IOC שהם… איך לומר… יצירתיים).
3. מגיע משהו חשוב? **Submit IOCs**:
   - אם זה אחד־אחד: Single.
   - אם זה מתוך דוח: Paste (והמערכת תעשה סדר).
   - אם זה הגיע כקובץ: TXT/CSV עם Preview.
4. **Search & Investigate**:
   - מחפשים IOC לפי value / analyst / tag / campaign / date.
   - מוסיפים **IOC Note** כדי שמי שיבוא אחריך יבין למה זה פה.
   - עורכים/מבטלים/מוחקים — וכל זה נכנס להיסטוריה.
5. אם החקירה היא “קמפיינית”: נכנסים ל־**Campaign Graph**, קושרים IOCs, ומסתכלים על ההקשרים.
6. אם יש חתימה: **YARA Manager**, בודקים syntax, מעלים, שולחים ל‑pending, ואז אדמין מאשר.
7. ובסוף? Champs וריפורטים. כי גם SOC צריך קצת “מסגרת”.

-

<a id="he-feeds-taxii"></a>

## פידים, TAXII, ומה פתאום צריך גם וגם

### למה יש גם `/feed/...` וגם `/taxii2/...`?

- `/feed/...` זה “מינימום חיכוך”: ציוד ותיק, FW, EDR, SIEM, כל מי שרוצה **plain-text**.
- `/taxii2/...` זה סטנדרט: TAXII 2.1 / STIX 2.1 ללקוחות תואמים.

הכל מגיע מאותו מקור אמת (DB), אבל הקהל שונה.

### פידים (Plain text + פורמטים)

הפידים הם ציבוריים (אין Flask-Login) ולכן ההמלצה היא **Firewall**.  
במערכת אמיתית זה intentional: הפיד מיועד לצרכנים חיצוניים, לא ל־UI.

- סטנדרטי: `/feed/ip`, `/feed/domain`, `/feed/url`, `/feed/hash`, `/feed/md5`, `/feed/sha1`, `/feed/sha256`, `/feed/email`
- Palo Alto EDL: `/feed/pa/ip`, `/feed/pa/domain`, `/feed/pa/url` (ללא פרוטוקול), `/feed/pa/md5`, `/feed/pa/sha256`, `/feed/pa/email`
- Check Point (CSV): `/feed/cp/ip`, `/feed/cp/domain`, `/feed/cp/url`, `/feed/cp/hash`, `/feed/cp/md5`, `/feed/cp/sha1`, `/feed/cp/sha256`
- Cisco ESA: `/feed/esa/email` (comma-separated)
- Trellix ePO: `/feed/epo/files-list`, `/feed/epo/<ticket_id>`
- STIX bundle “נוח”: `/feed/stix`
- YARA: `/feed/yara-list`, `/feed/yara-content/<filename>`

הקוד:

- `routes/feeds.py`
- `utils/feed_cache.py` (מטמון/הגשה)
- `docs/YARA_FEEDS_AND_PENDING.md` (למה pending לא יוצא בפיד)

### TAXII 2.1 / STIX 2.1

השרת נמצא ב־`routes/taxii_server.py` תחת `/taxii2/...`.

דוגמה בסיסית (תיאור, לא פקודה “מחייבת”):

- `GET /taxii2/` (Discovery)
- `GET /taxii2/ziochub/collections/` (Collections)
- Objects/Manifest תחת ה־collection

חשוב: לקוחות צריכים לשלוח:

- `Accept: application/taxii+json;version=2.1`

-

<a id="he-integrations"></a>

## אינטגרציות (אופציונלי)

הקטע היפה באינטגרציות: הן קיימות, אבל הן לא תוקעות אותך. אם אין לך LDAP — אתה עדיין עובד. אם אין לך MISP — אתה עדיין עובד. אם יש לך הכל — יופי, זה מתחבר.

### MISP

- Pull: job מתוזמן (`misp_sync_job.py`) + לוגיקה ב־`utils/misp_sync.py`
- Push (אופציונלי): `utils/misp_push.py`
- אדמין: בדיקה/סנכרון דרך `routes/admin.py`
- Systemd timer: `ziochub-misp-sync.timer`

### LDAP / AD

- לוגיקה: `utils/ldap_auth.py`
- מצבי auth: local / ldap / ldap עם fallback
- בדיקות: `/api/ldap/health` + אדמין `/api/admin/ldap/test`

### Cisco ESA (Content Dictionaries)

- לוגיקה: `utils/cisco_esa.py`
- אדמין: `/api/admin/esa/test`
- אופציה “remove on expire” מחוברת ל־cleaner

### DXL/TIE (ePO reputation)

- לוגיקה: `utils/dxl_tie.py` (תלוי חבילות, לא חובה)
- בדיקות/העלאות: `/api/admin/dxl/test`, `/api/admin/dxl/upload`

### GeoIP

- קובץ מקומי: `data/GeoLite2-City.mmdb`
- משפיע על Top Countries וכו’

### Syslog/CEF Audit

- לוגיקה: `utils/cef_logger.py`
- קובץ לוג אופייני (בפרודקשן): `data/audit_cef.log`
- אפשר גם UDP syslog (אופציונלי)

-

<a id="he-admin"></a>

## אדמין ומה הוא שולט

הדבר הכי חשוב באדמין: לא “לשחק” בפרודקשן בלי להבין. מצד שני — מישהו חייב להחזיק את ההגה.

מסכים עיקריים (HTML תחת `templates/admin/` + API ב־`routes/admin.py`):

- Settings: הפעלה/כיבוי פידים/TAXII ציבוריים, מדיניות sanity, ועוד.
- Integrations: MISP/LDAP/ESA/DXL ועוד בדיקות.
- Allowlist: ניהול allowlist.
- Users: ניהול משתמשים, active/inactive, אווטארים.
- Certificate: תעודת SSL.
- Scoring: שיטת ניקוד Champs.
- Logs: Tail לוגים.
- Admin Inbox: snapshot של pending YARA/תהליכים.

API בולט:

- `GET /api/admin/inbox`
- `GET/POST /api/admin/settings`
- `GET/POST /api/admin/allowlist`
- `GET/POST /api/admin/scoring-method`

-

<a id="he-data"></a>

## מודל נתונים (SQLite)

SQLite הוא לא “צעצוע”. הוא פשוט כלי נכון כשאתה רוצה:

- קובץ אחד (`ziochub.db`)
- גיבוי פשוט
- ושאילתות עקביות בלי להרים DB server

קבצים:

- מודלים: `models.py`
- הרחבה: `extensions.py`

טבלאות עיקריות (מילים פשוטות):

- `users`, `user_profiles`, `user_sessions`
- `iocs`, `ioc_history`, `ioc_notes`
- `campaigns`
- `yara_rules`
- `sanity_exclusions`
- `system_settings`
- Champs: `activity_events`, `team_goals`, `champ_rank_snapshots`

-

<a id="he-security"></a>

## אבטחה (בגובה העיניים)

- התחברות: Flask‑Login
- סיסמאות: hashing דרך Werkzeug (scrypt)
- פידים/TAXII: **ציבוריים** → חייבים הגבלת רשת (FW / reverse proxy)
- ORM (SQLAlchemy): שאילתות פרמטריות (פחות “SQL injection surprise”)
- `DEV_MODE`: לא בפרודקשן
- Audit: CEF לקובץ + אופציונלי syslog

-

<a id="he-install"></a>

## התקנה והרצה

### פיתוח מקומי

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

ברירת מחדל: `admin` / `admin` (ואז מחליפים מיד כי אנחנו אנשים טובים).

### ייצור (setup)

הסקריפט `setup.sh` עושה: משתמש מערכת `ziochub`, תיקייה `/opt/ziochub`, venv, תלויות, DB, systemd units, הפעלה.

Offline:

- `package_offline.sh` על מחשב עם אינטרנט
- `setup.sh --offline` בשרת

-

<a id="he-ops"></a>

## שירותים, טיימרים ותחזוקה

בפרודקשן חיים על systemd:

- `ziochub.service` (Gunicorn)
- `ziochub-redirect.service` (HTTP→HTTPS, אם פרוס)
- `ziochub-cleaner.timer` (פקיעת IOC)
- `ziochub-backup.timer` (גיבויים)
- `ziochub-misp-sync.timer` (MISP)

סקריפטים שימושיים:

- `backup_ziochub.sh`
- `cleaner.py`
- `reset_data.py`
- `create_lab_users.py`
- `scripts/reset_admin_password.py`

-

<a id="he-demo"></a>

## DEMO סטטי (GitHub Pages)

### מה הדמו עושה ולמה הוא קיים

הדמו הוא “קופסה סגורה” שמדמה מערכת אמיתית בלי backend. זה מעולה ל:

- הדגמות
- תיעוד
- סרטוני הדרכה
- להראות UI בלי לפתוח רשת פנימית

### הבילדר של הדמו

הסקריפט:

- `demo/ziochub-demo/build_demo.py`

קלטים:

- `users/users.json`
- `indicators/*.txt`, `indicators/campains.txt`
- `indicators/*.yar`

פלט:

- `demo/ziochub-demo/site/index.html` (הממשק)
- `demo/ziochub-demo/site/static/` (CSS/JS)
- `demo/ziochub-demo/site/data/*.json` (דאטה)
- `demo/ziochub-demo/site/assets/*` (avatars/yara)

### והחלק החשוב: פידים בדמו — סטטי אמיתי

כדי שהדמו יעבוד גם תחת GitHub Pages בתת־נתיב (למשל `https://cybugs3.github.io/projects/ziochub-demo/site/`) נבנים **דפים סטטיים**:

- `demo/ziochub-demo/site/feed/<type>/index.html`

הלינקים ב־Feed Catalog בדמו הם יחסיים (`./feed/ip/`) ולא `/feed/ip`, כדי שלא “יברחו” לרוט של הדומיין.

-

<a id="he-architecture"></a>

## ארכיטקטורת קוד — איפה כל דבר חי

Backend:

- `app.py` (bootstrap)
- `routes/*.py` (blueprints)

Frontend:

- `templates/index.html` (SPA)
- `static/js/*.js`
- `static/css/style.css`
- `static/i18n/en.json`, `static/i18n/he.json`

מסמכים שימושיים:

- `../TROUBLESHOOTING.md`
- `../DXL_INTEGRATION.md`
- `../CSS_DESIGN_AUDIT_REPORT.md`

-

<a id="he-troubleshooting"></a>

## פתרון תקלות נפוצות

- **DB locked (SQLite)**: בדרך כלל מופע כפול או פעולה כבדה. עושים restart, בודקים timers.
- **YARA check syntax נכשל**: לוודא `yara-python` מותקן ב־venv הנכון.
- **פידים לא זמינים**: בדקו admin setting של “feeds_public_enabled” + FW.
- **GitHub Pages שובר `/feed/...`**: חייבים לינקים יחסיים (בדמו זה כבר מטופל בבילד).

-

<a id="he-oss"></a>

## קרדיטים וקוד פתוח

ZIoCHub נשענת על: Flask, SQLAlchemy, Tailwind, Chart.js, vis-network, Prism, marked, Turndown, jsPDF, html2canvas ועוד.  
הרשימה באנגלית (עם פרטים) נמצאת כאן: [`../../README.md`](../../README.md)


