# DXL / TIE Integration — ZIoCHub

מסמך זה מתאר את אינטגרציית OpenDXL / TIE ב-ZIoCHub: חיבור ל-fabric של ePO, העלאת קבצי provisioning, בדיקת חיבור, והפצת Hash IOCs ל-TIE.

---

## 1. סקירה

- **מטרה:** כשאנליסט מזין **Hash** (MD5 / SHA1 / SHA256) ב-ZIoCHub, המערכת מעדכנת אוטומטית את **TIE** (Threat Intelligence Exchange) ב-ePO כ-**Known Malicious**, כך ש-endpoints שמשתמשים ב-TIE יראו את ה-reputation.
- **תשתית:** OpenDXL (Data Exchange Layer) — ZIoCHub מתחבר כ-**DXL client** ל-DXL fabric (brokers), ושולח הודעות ל-TIE service על ה-fabric דרך `TieClient.set_file_reputation`. זו **לא** פרסום הודעות גeneric לכל ה-BUS; רק עדכוני reputation ל-TIE.
- **סוגי IOC:** רק **Hash**. Domain, IP, URL, Email — לא נשלחים בנתיב OpenDXL.
- **מקום ההגדרה ב-UI:** **Admin Panel → Integrations → Push IOC → OpenDXL**  
  (לא ב-Settings; אינטגרציות threat-intel push/pull מרוכזות תחת Integrations).

מדריך מפורט עם קישורים למסמכים רשמיים מוצג גם ב-UI באותו מסך (מדריכים מתקפלים + טבלת קבצים).

---

## 2. חיבור ZIoCHub ל-DXL fabric (ePO / Trellix)

### 2.1 בצד ePO

1. **וודאו ש-DXL פעיל** — brokers רצים; מ-ePO Server יש גישת TCP ל-broker hosts (בדרך כלל פורט **8883**).
2. **Provision DXL client ל-Linux** — ePO UI (DXL / Client Management / Provisioning) או CLI:
   ```bash
   dxlclient provisionconfig <output-dir> <epo-host> <client-name>
   ```
   ברירת מחדל HTTPS ל-ePO: **8443**; `-t <port>` אם שונה.  
   מסמכים: [OpenDXL provisioning overview](https://opendxl.github.io/opendxl-client-python/pydoc/provisioningoverview.html) · [CLI provisioning (basic)](https://opendxl.github.io/opendxl-client-python/pydoc/basiccliprovisioning.html)
3. **הרשאות TIE ב-ePO** — **Server Settings → DXL Topic Authorization** — אפשרו ל-client certificate **Send** על קבוצת **TIE Server Set Enterprise Reputation** (topic `/mcafee/service/tie/file/reputation/set`).  
   בלי זה Test Connection עלול להצליח ב-broker ולהיכשל ב-TIE.  
   מסמכים: [Authorization overview](https://opendxl.github.io/opendxl-client-python/pydoc/topicauthoverview.html) · [TieClient.set_file_reputation](https://opendxl.github.io/opendxl-tie-client-python/pydoc/dxltieclient.client.html#dxltieclient.client.TieClient.set_file_reputation)

### 2.2 בצד שרת ZIoCHub (Linux)

1. **חבילות Python** (אותו venv כמו Gunicorn):
   ```bash
   pip install -r requirements.txt
   # או:
   pip install dxlclient dxltieclient
   ```
   גרסאות מינימום: `dxlclient>=5.0.0`, `dxltieclient>=0.3.0`.
2. **קבצי provisioning** — אחת משתי דרכים:
   - **דרך Admin UI:** Integrations → Push IOC → OpenDXL → העלאת 4 הקבצים (ראו §3).
   - **ידנית:** העתקה ל-`data/dxl/` תחת תיקיית ה-data של ZIoCHub (SMB share / `DATA_DIR`).

3. **Restart** (אחרי התקנת חבילות): `systemctl restart ziochub` (או לפי סביבתכם).

---

## 3. העלאת קבצים ב-Admin UI

במסך **Integrations → Push IOC → OpenDXL** יש 4 שדות upload. ZIoCHub שומר **שמות קבועים** תחת `data/dxl/` (נתיב מלא: `<DATA_DIR>/dxl/`).

| שדה ב-UI | תוכן | שם מקור טיפוסי (ePO / CLI) | נשמר בשרת |
|----------|------|----------------------------|-----------|
| **dxlclient.config** | רשימת brokers + נתיבי certs | `dxlclient.config` | `data/dxl/dxlclient.config` |
| **Broker certificate chain** | CA bundle ל-brokers (`BrokerCertChain`) | `brokercerts.crt`, `ca-bundle.crt` | `data/dxl/brokercerts.crt` |
| **Client certificate** | תעודת client על ה-fabric | `client.crt` | `data/dxl/client.crt` |
| **Client private key** | מפתח פרטי תואם | `client.key` | `data/dxl/client.key` (mode 600) |

**התנהגות backend** (`POST /api/admin/dxl/upload` ב-`routes/admin.py`):

- ניתן להעלות קובץ אחד או כמה יחד.
- בעת upload של `dxlclient.config`, ZIoCHub **כותב מחדש** את סקשן `[Certs]` כך ש-`BrokerCertChain`, `CertFile`, `PrivateKey` יצביעו לנתיבים המוחלטים תחת `data/dxl/`.
- סקשן `[Brokers]` **לא** נערך — חייב להגיע נכון מ-ePO.
- אחרי upload של config, `dxl_config_path` נשמר אוטומטית ב-SystemSetting.

**Path to dxlclient.config** — נתיב **מוחלט על Linux** (לא נתיב SMB מ-Windows). אחרי upload מה-UI השדה מתמלא לבד.

---

## 4. הגדרה והפעלה ב-ZIoCHub

1. **Integrations → Push IOC → OpenDXL**
2. העלו קבצי provisioning (§3) או הגדירו נתיב ידני ל-config קיים.
3. **Test connection** — חייבים לעבור כל השלבים:
   - Config file / Load config
   - Connect to broker
   - TIE set reputation (hash בדיקה)
4. **OpenDXL enabled = Yes** → **Save OpenDXL settings**
5. שליחת Hash חדש (Submit / bulk / staging) — push ל-TIE ברקע; כישלון **לא** מבטל שמירת IOC.

**Test Connection API:** `POST /api/admin/dxl/test` עם JSON `{ "dxl_config_path": "..." }`.

---

## 5. התקנה offline (Python packages)

1. **במכונה עם אינטרנט:**
   ```bash
   pip download dxlclient dxltieclient -d /path/to/wheels
   ```
2. **על שרת ZIoCHub (offline):**
   ```bash
   cd /path/to/wheels
   pip install --no-index --find-links . dxlclient dxltieclient
   ```

קבצי ePO/provisioning מועברים בדיסק/USB/SCP — אותו תהליך כמו §3.

---

## 6. מימוש נוכחי בקוד

| רכיב | מיקום | תיאור |
|------|--------|--------|
| הגדרות | `routes/admin.py` | `dxl_enabled`, `dxl_config_path` ב-`_SETTINGS_DEFAULTS`; שמירה ב-`save_settings()` |
| Upload | `routes/admin.py` | `POST /api/admin/dxl/upload` → `data/dxl/` + `_rewrite_dxl_config_certs_section` |
| Test | `routes/admin.py` | `POST /api/admin/dxl/test` |
| Runtime push | `utils/dxl_tie.py` | `push_hash_to_tie()`, `test_dxl_connection_steps()` |
| Trigger | `routes/ioc.py` | אחרי commit מוצלח של Hash (submit, bulk, ingest, staging, txt) אם `dxl_enabled == true` |
| UI | `templates/admin/partials/automation_panel_opendxl.html` | טופס, upload, מדריכים, Test |
| JS | `templates/admin/partials/automation_panel_scripts.html` | upload / save / test handlers |
| Health | `app.py` | `/health` → `checks.dxl` (configured / config_missing / disabled) |
| Audit | `utils/dxl_tie.py` | `DXL_TIE_PUSH`, `DXL_TIE_PUSH_FAIL` |
| תלויות | `requirements.txt` | `dxlclient`, `dxltieclient` |

---

## 7. מנגנון וידוא — סיכום

- **הגדרה:** Admin מעלה certs + config (או מגדיר path) ושומר.
- **Test Connection:** לפני Enable — config → broker → TIE reputation test. רק אם הכל ירוק, להפעיל production push.
- **Runtime:** Hash חדש → `push_hash_to_tie` ברקע; שגיאות ב-log/audit; IOC נשאר ב-DB.

---

## 8. Troubleshooting

| תסמין | סיבה נפוצה | פעולה |
|--------|------------|--------|
| DXL libraries fail | `dxlclient` / `dxltieclient` לא מותקנים ב-venv של Gunicorn | `pip install …` + restart |
| Config file not found | נתיב Windows/SMB במקום Linux | נתיב מוחלט על Linux; העדפה: upload דרך UI |
| Connect to broker fail | firewall, broker down, certs שגויים | בדיקת `[Brokers]`, TCP 8883, `brokercerts.crt` |
| TIE set reputation fail | חסרה הרשאת Send ב-ePO Topic Authorization | §2.1 שלב 3 |
| Hash לא ב-TIE | DXL disabled או לא Hash type | Enable + Test; Feed Pulse → Connections |

עדכון brokers אחרי שינוי ב-ePO: `dxlclient updateconfig <dir> <epo-host>` — [Updating config from CLI](https://opendxl.github.io/opendxl-client-python/pydoc/updatingconfigfromcli.html) — ואז re-upload של config.

---

## 9. What ZIoCHub Needs (English summary)

ZIoCHub needs a valid **`dxlclient.config`** (broker list + cert paths), readable **broker CA**, **client cert**, and **client key**. It connects with `DxlClient`, then uses `TieClient.set_file_reputation(KNOWN_MALICIOUS, …)` per hash. ePO must authorize the client for **TIE Server Set Enterprise Reputation**. Provisioning and authorization are done outside ZIoCHub; the app only consumes config and sends TIE messages. Failures do not roll back IOC storage.

**References:** [OpenDXL Python SDK](https://opendxl.github.io/opendxl-client-python/pydoc/index.html) · [OpenDXL TIE client overview](https://opendxl.github.io/opendxl-tie-client-python/pydoc/overview.html)

---

*מסמך זה מניח גרסאות תואמות של OpenDXL Python client ו-TIE client (Trellix/McAfee OpenDXL). UI מפורט: Admin → Integrations → Push IOC → OpenDXL.*
