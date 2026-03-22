# DXL / TIE Integration — ZIoCHub

מסמך זה מתאר את מה שצריך לעשות כדי להכניס תמיכת DXL (OpenDXL) במערכת ZIoCHub, כולל מנגנון וידוא שהאינטגרציה עובדת תקין.

---

## 1. סקירה

- **מטרה:** כשאנליסט מזין **Hash** (MD5 / SHA1 / SHA256) ב־ZIoCHub, המערכת תעדכן אוטומטית את **TIE** (Threat Intelligence Exchange) ב־ePO כ־**Known Malicious**, כך שה־endpoints במערכת יראו את ה־reputation.
- **תשתית:** OpenDXL (Data Exchange Layer) - ZIoCHub מתחבר כ־DXL client ל־DXL fabric (brokers), ושולח הודעות ל־TIE service על ה־fabric.
- **מקום ההגדרה:** Admin Panel → Settings → טאב חדש **DXL** (בדומה ל־LDAP, MISP, Syslog).

---

## 2. התקנה על שרת לינוקס (ZIoCHub + DXL)

צריך **שני מרכיבים**: (1) חבילות Python של OpenDXL, (2) קובץ קונפיג ותעודות מהחבילה ש־ePO מייצר ללינוקס.

### 2.1 חבילת ePO ללינוקס (תעודות + קונפיג)

ב־ePO אפשר להכין **חבילת provisioning** ל־DXL client ללינוקס. החבילה כוללת בדרך כלל:

- **dxlclient.config** - קובץ קונפיגורציה (נתיבי brokers, [Certs], [Brokers]).
- **קבצי תעודות ומפתחות** - למשל `brokercerts.crt`, `client.crt`, `client.key` (השמות יכולים להשתנות לפי גרסת ePO).

**תהליך מומלץ:**

1. ב־ePO: DXL → Provisioning (או Client Management) → ליצור client חדש / חבילה ל־**Linux**.
2. להוריד את החבילה (ארכיון או תיקייה) ולהעביר לשרת הלינוקס שבו רץ ZIoCHub.
3. על הלינוקס: לפרוק את החבילה לתיקייה קבועה (למשל `/opt/ziochub/certs/dxl/` - ראו להלן).
4. אם ב־`dxlclient.config` הנתיבים הם יחסיים - לוודא שהם יחסיים לאותה תיקייה, או לעדכן את הנתיבים בקובץ כך שיצביעו למיקום האמיתי של הקבצים.

**אין "נתיב ברירת מחדל" מצד ZIoCHub** - הנתיב לקובץ `dxlclient.config` נקבע בהגדרות Admin (Settings → DXL → Path to dxlclient.config). מומלץ לבחור מיקום אחד על השרת ולדבוק בו.

**נתיבים מומלצים (אחרי פריקת חבילת ePO):**

| תוכן | נתיב מומלץ (דוגמה) |
|------|----------------------|
| תיקיית DXL (כל החבילה) | `/opt/ziochub/certs/dxl/` |
| קובץ הקונפיג | `/opt/ziochub/certs/dxl/dxlclient.config` |
| תעודות broker + client (לפי מה ש־ePO יצר) | באותה תיקייה, למשל `brokercerts.crt`, `client.crt`, `client.key` |

אם בחרתם `/opt/ziochub/certs/dxl/` - ב־ZIoCHub תזינו **Path to dxlclient.config** = `/opt/ziochub/certs/dxl/dxlclient.config`. יש להקפיד שהמשתמש שמריץ את ZIoCHub (למשל `www-data` או `ziochub`) יוכל לקרוא את כל הקבצים בתיקייה.

### 2.2 התקנת חבילות Python — עם אינטרנט

על השרת הלינוקס (בסביבה שבה רץ ZIoCHub, למשל venv):

```bash
# אם יש לכם requirements.txt עם כל התלויות (כולל DXL):
pip install -r requirements.txt

# או רק חבילות DXL:
pip install dxlclient dxltieclient
```

גרסאות מינימליות מומלצות: `dxlclient>=5.0.0`, `dxltieclient>=0.3.0` (כמו ב־requirements.txt של ZIoCHub).

### 2.3 התקנת חבילות Python — מצב OFFLINE (ללא אינטרנט)

1. **במכונה עם אינטרנט** (Windows או לינוקס אחר):
   - צור סביבה עם אותו גרסת Python כמו על השרת (למשל 3.10).
   - הורד חבילות + תלויות ל־wheel:
     ```bash
     pip download dxlclient dxltieclient -d /path/to/wheels
     ```
   - העתק את תיקיית ה־wheels (כולל כל קבצי ה־.whl) לשרת הלינוקס (USB, SCP, וכו').

2. **על שרת הלינוקס (OFFLINE)**:
   ```bash
   cd /path/to/wheels
   pip install --no-index --find-links . dxlclient dxltieclient
   ```
   או להתקין את כל הקבצים:
   ```bash
   pip install --no-index --find-links . *.whl
   ```

אם ZIoCHub רץ ב־venv, להריץ את הפקודות בתוך ה־venv של ZIoCHub.

### 2.4 סיכום התקנה

| שלב | עם אינטרנט | OFFLINE |
|-----|-------------|---------|
| חבילות Python | `pip install -r requirements.txt` או `pip install dxlclient dxltieclient` | `pip download` במכונה עם רשת → העברה → `pip install --no-index --find-links . ...` על השרת |
| תעודות + קונפיג | חבילת ePO ללינוקס → הורדה → פריקה לתיקייה (למשל `/opt/ziochub/certs/dxl/`) | אותו דבר (העברת החבילה בדיסק/USB/רשת פנימית) |
| הגדרה ב־ZIoCHub | Admin → Settings → DXL: Path = נתיב מלא ל־`dxlclient.config` (למשל `/opt/ziochub/certs/dxl/dxlclient.config`) | זהה |

אחרי ההתקנה: להפעיל **Test Connection** בטאב DXL; אם כל השלבים ירוקים - להשאיר DXL Enabled.

---

## 3. רשימת משימות — מה לעשות במערכת ZIoCHub

### 3.1 הגדרות (SystemSetting + Admin UI)

| משימה | תיאור |
|-------|--------|
| הוספת מפתחות DXL ל־`_SETTINGS_DEFAULTS` | ב־`routes/admin.py`: להוסיף למשל `dxl_enabled`, `dxl_config_path` (או שדות נפרדים: broker list, cert paths - ראו להלן). |
| שמירת הגדרות DXL ב־`save_settings()` | להוסיף `dxl_keys` (רשימת המפתחות) ולולאה ששומרת אותם ב־`_set_setting` כשמגיע POST עם הערכים. |
| טאב DXL ב־`templates/admin/settings.html` | כפתור טאב "DXL" ברצועת הטאבים; פאנל עם טופס (Enabled, path לקונפיג או שדות broker/certs) + כפתור **"Test Connection"**. |
| מילוי טופס בהגדרות קיימות | ב־`admin_settings()` (ה־view של דף Settings) להעביר ל־template את ערכי `dxl_*` מ־`_get_setting`. |

**הערה על קונפיגורציה:**  
- **אפשרות א' (מומלצת):** שדה יחיד `dxl_config_path` - נתיב מלא לקובץ `dxlclient.config` (כפי שנוצר ב־provisioning). Test Connection ו־runtime טוענים את הקובץ.  
- **אפשרות ב':** שדות נפרדים: `dxl_broker_list` (למשל `host1:8883,host2:8883`), `dxl_broker_certs_path`, `dxl_client_cert_path`, `dxl_client_key_path` (ואולי `dxl_client_key_password`). אז ב־runtime בונים אובייקט config מתוך השדות במקום מקובץ.

### 3.2 Test Connection — מנגנון וידוא

| משימה | תיאור |
|-------|--------|
| endpoint `POST /api/admin/dxl/test` | ב־`routes/admin.py`, עם `@admin_required`. מקבל JSON עם פרטי DXL (או path) כמו ב־LDAP test. |
| לוגיקת הטסט | 1) טעינת קונפיג (מקובץ או משדות). 2) יצירת `DxlClient`, `client.connect()`. 3) (אופציונלי) יצירת `TieClient`, קריאה ל־`set_file_reputation` עם hash בדיקה (Known Malicious) ואז בדיקה שהקריאה הצליחה. 4) `client.disconnect()`. להחזיר `{ success: true/false, steps: [ { step, status, message } ] }` או `{ success, message }`. |
| הצגה ב־UI | כפתור "Test Connection" בטאב DXL; לחיצה שולחת POST עם הערכים מהטופס; הצגת תוצאה (הצלחה / כישלון + פירוט שלבים) כמו ב־LDAP (log area עם צעדים ו־✓/✗). |

חשוב: **Test Connection** הוא המנגנון המרכזי שמוודא שהחיבור ל־broker עובד ושה־TIE מקבל עדכון. מומלץ שהטסט יכלול גם שליחת reputation לבדיקה (לא רק connect/disconnect).

### 3.3 עדכון TIE בעת הזנת Hash

| משימה | תיאור |
|-------|--------|
| Helper לשליחה ל־TIE | מודול/פונקציה (למשל `utils/dxl_tie.py`): טעינת קונפיג, חיבור DXL, יצירת `TieClient`, `set_file_reputation(TrustLevel.KNOWN_MALICIOUS, { HashType: value })`, ניתוק. מיפוי אורך `value`: 32→MD5, 40→SHA1, 64→SHA256 (128→SHA512 אם TIE תומך). |
| קריאה אחרי שמירת Hash | ב־`routes/ioc.py` בכל מקום שמכניסים IOC מסוג Hash ל־DB (submit_ioc, bulk, ingest, submit_staging): אחרי `_commit_with_retry()` מוצלח, אם `_get_setting('dxl_enabled') == 'true'` - לקרוא ל־helper עם ה־hash. לעטוף ב־try/except ו־log; כישלון לא אמור לבטל את שמירת ה־IOC. |
| תלויות | להוסיף ל־`requirements.txt`: `dxlclient`, `dxltieclient` (שמות החבילות ב־PyPI). Import רק כשצריך (אם DXL disabled - לא לטעון). |

### 3.4 אופציונלי: וידוא נוסף

| משימה | תיאור |
|-------|--------|
| Health check | ב־`/health`: אם `dxl_enabled == true`, אפשר להוסיף בדיקה (למשל חיבור קצר או בדיקת קיום קובץ config) ולכלול ב־`checks.dxl` סטטוס. |
| Audit | ב־`audit_log` לרשום אירוע כשנשלח hash ל־TIE (למשל `DXL_TIE_PUSH` עם hash מקוצר) וכשנכשל (עם סיבה כללית). |

---

## 4. מנגנון וידוא — סיכום

- **הגדרה נכונה:** Admin מגדיר DXL (path או שדות) ושומר.
- **Test Connection:** לפני שמפעילים "Enabled", לוחצים Test Connection ורואים שלבים: טעינת config → חיבור ל־broker → (אופציונלי) שליחת reputation בדיקה ל־TIE → הצלחה/כישלון. רק אם הטסט עובר - להשאיר DXL enabled.
- **ב־runtime:** כל Hash שנשמר ב־ZIoCHub מפעיל שליחה ל־TIE אם DXL enabled; שגיאות נרשמות ל־log (ואולי ל־audit) ולא מונעות שמירת ה־IOC.

---

## 5. הערות באנגלית — What ZIoCHub Needs for Successful Broker Connection and TIE Updates

The following is from **ZIoCHub’s point of view only**: what the application must have and do so that it can connect to the DXL broker and update TIE correctly. It does not cover ePO/server-side provisioning or certificate issuance.

---

### 5.1 Configuration ZIoCHub Must Have

- **Broker connectivity:**  
  - A valid **broker list** (one or more `host:port`, e.g. `epo-broker.example.com:8883`).  
  - ZIoCHub uses this to connect to the DXL fabric; without it, connection will fail.

- **Certificates and keys:**  
  - **Broker certificates** (e.g. `brokercerts.crt` or equivalent bundle path) so the client can authenticate the broker(s).  
  - **Client certificate** (`client.crt` or equivalent) and **client private key** (`client.key` or equivalent), signed by a CA that the DXL fabric (ePO or OpenDXL Broker) trusts.  
  - ZIoCHub only needs the **paths** to these files (or their content if stored in DB); it does not create or sign certificates. If any of these are missing or invalid, connection will fail.

- **Optional:**  
  - Passphrase for the client private key, if it is encrypted. ZIoCHub must be able to provide it when loading the key.

- **Single-file option:**  
  - Alternatively, a path to a single **`dxlclient.config`** file that already contains broker list, `BrokerCertChain`, `CertFile`, and `PrivateKey` (and optional passphrase). Then ZIoCHub only needs to read this path and load the config; no need to expose separate fields.

---

### 5.2 What ZIoCHub Must Do to Connect Successfully

- **Load configuration:**  
  - Read the broker list and certificate/key paths (from the config file or from stored settings).  
  - Ensure the referenced files exist and are readable by the process running ZIoCHub.

- **Create DXL client and connect:**  
  - Use the OpenDXL Python client to create a `DxlClient` with the loaded config.  
  - Call `client.connect()`.  
  - Success means ZIoCHub is connected to the fabric. Failure usually means: wrong broker address/port, network/firewall issue, or invalid/missing certificates (broker or client).

- **Test Connection:**  
  - Implement an admin “Test Connection” that performs the steps above and, ideally, also sends a test reputation to TIE (e.g. a known test hash) and checks for success.  
  - Return clear success/failure and, on failure, a short message or steps (e.g. “Connect to broker - fail: connection refused”) so the admin can fix broker/certificate/network issues.

---

### 5.3 What ZIoCHub Must Do So TIE Is Updated Correctly

- **Use TIE client over the same DXL connection:**  
  - After `client.connect()`, create a `TieClient(client)` and use it to send reputation updates.  
  - ZIoCHub does not talk to ePO HTTP API for TIE; it sends DXL messages to the TIE service on the fabric.

- **Send the correct topic/API:**  
  - Call the TIE API to **set file reputation** (e.g. `set_file_reputation` or the External Reputation variant recommended for automated integrations).  
  - Use trust level **Known Malicious** for hashes submitted by analysts in ZIoCHub.  
  - Payload must include the hash type (MD5 / SHA1 / SHA256, and SHA512 if supported) and the hash value(s). ZIoCHub stores a single hash value per IOC; map length 32→MD5, 40→SHA1, 64→SHA256.

- **Client authorization on the fabric:**  
  - The DXL client identity (certificate) used by ZIoCHub must be **allowed by ePO** to send messages to the TIE “set reputation” topic (e.g. permission group “TIE Server Set Enterprise Reputation” or “Set External Reputation”).  
  - ZIoCHub cannot grant itself this permission; the ePO admin must assign it. If the client is not authorized, the connection to the broker may succeed but the TIE set-reputation call will fail (e.g. permission denied). Test Connection should include a real set-reputation attempt so this is detected.

- **Error handling:**  
  - On set-reputation failure (timeout, permission, or TIE error), ZIoCHub should log the error and optionally audit it. It should **not** roll back or block the IOC submission in the DB; the Hash remains in ZIoCHub even if TIE update fails.

---

### 5.4 Summary (English)

- ZIoCHub needs: **broker list**, **broker cert(s)**, **client cert**, **client key** (and optional passphrase), or a single **dxlclient.config** path.  
- ZIoCHub must: **load config**, **connect** to the fabric, then use **TieClient** to **set file reputation** (Known Malicious) for each submitted hash.  
- **Test Connection** should verify both broker connectivity and a real TIE set-reputation call, so that misconfiguration or missing ePO permissions are detected before relying on automatic updates.  
- Provisioning and ePO authorization are done **outside** ZIoCHub; ZIoCHub only consumes the resulting config and sends the correct DXL/TIE messages.

---

## 6. קבצים רלוונטיים בפרויקט (לשינוי/הוספה)

| קובץ | שימוש |
|------|--------|
| `routes/admin.py` | `_SETTINGS_DEFAULTS`, `save_settings()`, `get_settings`, `admin_settings()`, `POST /api/admin/dxl/test` |
| `templates/admin/settings.html` | טאב DXL, טופס, כפתור Test Connection, JS לשליחה והצגת תוצאה |
| `routes/ioc.py` | אחרי שמירת Hash - קריאה ל־helper DXL/TIE אם `dxl_enabled` |
| `utils/dxl_tie.py` (חדש) | טעינת config, חיבור, TieClient, set_file_reputation, מיפוי hash length→type |
| `requirements.txt` | `dxlclient`, `dxltieclient` |
| `app.py` (אופציונלי) | אם מוסיפים DXL ל־`/health` |

---

*מסמך זה מניח גרסאות תואמות של OpenDXL Python client ו־TIE client (למשל מהדוקומנטציה והדוגמאות של Trellix/McAfee OpenDXL).*
