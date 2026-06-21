# דוח QA — ZIoCHub v2.0 Beta

**תאריך:** 21 ביוני 2026  
**גרסה:** v2.0 Beta  
**סוג בדיקה:** Code Review + מיפוי Inputs (ללא E2E על שרת)  
**מטרה:** מסמך עבודה לתיקון ממצאים לפי עדיפות

---

## איך להשתמש במסמך

1. עבור על [Checklist ידני](#8-checklist-ידני-לשרת) וסמן מה נבדק.
2. לכל ממצא ב-[טבלת מעקב](#4-טבלת-מעקב-ממצאים) — עדכן **סטטוס** (`Open` / `In Progress` / `Fixed` / `Won't Fix`).
3. התחל מתיקוני [P0](#41-p0--קריטי), אחר כך [P1](#42-p1--גבוה), וכן הלאה.
4. אחרי תיקון — הרץ `python -m pytest tests/ -v` ו-restart: `sudo systemctl restart ziochub`.

---

## 1. סיכום מנהלים

ZIoCHub היא מערכת Flask מלאה עם עשרות נקודות קלט — IOC, YARA, Search, Campaigns, Champs, Admin, Integrations. **הליבה העסקית מיושמת היטב** (validation IOC, staging, YARA syntax, auth, audit), אך יש **פערים ב-authorization**, **חשיפת מידע**, ו-**הגבלות גודל** חסרות ב-uploads.

| רמה | כמות | משמעות |
|-----|------|--------|
| 🔴 P0 — קריטי | 4 | דורש תיקון לפני production חשוף |
| 🟠 P1 — גבוה | 8 | סיכון אבטחה / שלמות נתונים |
| 🟡 P2 — בינוני | 10 | UX, עקביות, DoS |
| 🟢 P3 — נמוך | 10+ | polish, הודעות, edge cases |
| ✅ תקין | רוב הזרימות | IOC submit, YARA workflow, auth בסיסי |

**מגבלה:** לא בוצעה הרצה End-to-End על שרת Ubuntu. יש להשלים עם Checklist ידני (סעיף 8).

---

## 2. מתודולוגיה

| שכבה | מה נבדק |
|------|---------|
| Frontend | `templates/*.html`, `static/js/*.js` — forms, file upload, modals |
| Backend | `routes/*.py` — POST/PUT/DELETE, auth decorators, validation |
| Utilities | `utils/validation.py`, `refanger.py`, `tags.py`, `sanity_checks.py` |
| Tests | `tests/` — unit tests (~20 קבצים); **אין E2E / UI tests** |

---

## 3. מפת כיסוי Inputs

| מודול | # Inputs | Client validation | Server validation | API עיקרי |
|-------|----------|-------------------|-------------------|-----------|
| Login / Password | 5 | `required`, min 8 (change pw) | LDAP/local | `POST /login`, `/change-password` |
| Profile | 7 | maxlength, file type | partial | `PUT /api/profile`, avatar POST |
| IOC Single | 8 | regex, private IP warn | מלא + sanity | `/api/preview-single`, `/api/submit-ioc` |
| IOC Bulk (TXT/CSV/Paste) | 15+ | file type, staging | מלא (preview חלקי) | `/api/preview-*`, `/api/submit-staging` |
| Search / Edit / Delete | 10 | reason required (delete) | חלקי | `/api/search`, `/api/edit`, `/api/revoke` |
| IOC Notes | 1 | maxlength 2000 | content length | `POST /api/ioc-notes` |
| YARA Upload/Write | 8 | `.yar`, syntax check | 512KB, syntax | `/api/upload-yara`, `/api/yara/*` |
| Campaigns | 12 | name required | tags, image 8MB | `/api/campaigns/*` |
| Playbook | 6+ | URL type | חלש | `/api/playbook` |
| Champs | 8 | min/max numbers | admin-only (goal) | `/api/champs/*` |
| Admin Users | 10 | minlength | password **4 chars** | `/api/admin/users` |
| Admin Settings | 80+ | מינימלי | whitelist keys | `POST /api/admin/settings` |
| Admin Integrations | 50+ | dynamic rows | varies | settings + test endpoints |
| Allowlist / Cert / Downstream | 8 | partial | allowlist 500KB | `/api/admin/*` |
| Inbox (Notifications) | 3 | — | auth | `/api/inbox/*` |

---

## 4. טבלת מעקב ממצאים

| ID | חומרה | סטטוס | כותרת | קובץ/Route |
|----|--------|--------|-------|------------|
| QA-001 | P0 | Open | קריאת YARA ללא אימות | `GET /api/view-yara/<filename>` |
| QA-002 | P0 | Open | מחיקה/עריכת IOC ללא בדיקת בעלות | `POST /api/revoke`, `POST /api/edit` |
| QA-003 | P0 | Open | Open Redirect אחרי Login | `routes/auth.py` — `next` param |
| QA-004 | P0 | Open | Bulk upload ללא הגבלת גודל מספקת | `/api/bulk-csv`, `/api/upload-txt`, preview |
| QA-005 | P1 | Open | Campaign/Playbook — כל משתמש יכול לשנות | `/api/campaigns/*`, `/api/playbook` |
| QA-006 | P1 | Open | Ingest API חלש מ-UI Submit | `POST /api/v1/ioc` |
| QA-007 | P1 | Open | סיסמת Admin — מינימום 4 תווים | `POST /api/admin/users` |
| QA-008 | P1 | Open | Avatar upload ללא הגבלת גודל | profile + admin avatar |
| QA-009 | P1 | Open | IOC value > 1024 chars | `utils/validation.py` |
| QA-010 | P1 | Open | Tag governance bypass בשגיאה | `_validate_tags_or_reject()` |
| QA-011 | P1 | Open | DEV_MODE backdoor | `routes/auth.py` |
| QA-012 | P1 | Open | Submit-staging — 0 items ללא feedback | `/api/submit-staging` |
| QA-013 | P2 | Open | Paste preview — אין cap על אורך | `/api/preview-paste` |
| QA-014 | P2 | Open | Notes — אין בדיקת IOC קיים | `/api/ioc-notes` |
| QA-015 | P2 | Open | Revoke reason — אין max length | `/api/revoke` |
| QA-016 | P2 | Open | Admin API 500 → לפעמים HTTP 200 | `routes/admin.py` |
| QA-017 | P2 | Open | הודעות allowlist לא עקביות | IOC routes |
| QA-018 | P2 | Open | YARA resubmit — campaign לא קיים → None | `/api/yara/resubmit` |
| QA-019 | P2 | Open | Ticker messages — text ריק מותר | `/api/champs/ticker-messages` |
| QA-020 | P2 | Open | אין rate limiting על login | `POST /login` |
| QA-021 | P2 | Open | Profile כפול (modal + `/profile`) | templates + JS |
| QA-022 | P2 | Open | Bulk SMART grouping — לא מתועד ב-UI | Champs SMART #8 |

---

## 4.1 P0 — קריטי

### QA-001 — קריאת YARA ללא אימות

| שדה | ערך |
|-----|-----|
| **Route** | `GET /api/view-yara/<filename>` |
| **קובץ** | `routes/yara.py` (~שורה 655) |
| **סטטוס** | Open |
| **סיכון** | תוכן כלל YARA (approved + pending) נגיש ללא login |

**תיאור:** Endpoint ללא `@login_required`. כל מי שמכיר/מנחש שם קובץ יכול לקרוא את התוכן.

**שחזור:**
```bash
curl -s "https://<host>/api/view-yara/example.yar"
# ללא cookie — מצפים ל-401, בפועל 200 + content
```

**תיקון מומלץ:**
- הוסף `@login_required`
- אופציונלי: admin/owner בלבד ל-pending rules

---

### QA-002 — מחיקה/עריכת IOC ללא בדיקת בעלות

| שדה | ערך |
|-----|-----|
| **Routes** | `POST /api/revoke`, `POST /api/edit` |
| **קובץ** | `routes/search.py` |
| **סטטוס** | Open |
| **סיכון** | כל משתמש מחובר יכול למחוק/לערוך IOC של משתמש אחר |

**שחזור:**
1. Login כ-`analyst1`
2. Search → מצא IOC של `analyst2`
3. Delete / Edit → מצליח

**תיקון מומלץ:**
```python
# הרשאה: admin OR row.user_id == current_user.id OR row.analyst == current_user.username
```

---

### QA-003 — Open Redirect אחרי Login

| שדה | ערך |
|-----|-----|
| **קובץ** | `routes/auth.py` (~שורה 206) |
| **סטטוס** | Open |
| **סיכון** | Phishing / redirect לדומיין חיצוני |

**קוד בעייתי:**
```python
next_url = request.args.get('next') or url_for('index')
return redirect(next_url)
```

**שחזור:** `/login?next=https://evil.com` → redirect חיצוני

**תיקון מומלץ:** לאשר רק paths יחסיים (`/`, `/search`, וכו') — דחה `//`, `http://`, `https://`.

---

### QA-004 — Bulk upload ללא הגבלת גודל מספקת

| שדה | ערך |
|-----|-----|
| **Routes** | `/api/bulk-csv`, `/api/upload-txt`, `/api/preview-*` |
| **סטטוס** | Open |
| **סיכון** | DoS / OOM — `file.read()` מלא לזיכרון |

**הערה:** Flask `MAX_CONTENT_LENGTH=16MB` קיים ב-`app.py`, אך paste JSON ו-ingest API ללא cap נוסף.

**שחזור:** העלה CSV 15MB+ עם אלפי שורות

**תיקון מומלץ:**
- cap על מספר שורות ב-preview
- streaming/chunked parsing ל-CSV גדול
- הודעת שגיאה ברורה כשחורגים מהמגבלה

---

## 4.2 P1 — גבוה

### QA-005 — Campaign/Playbook — כל משתמש יכול לשנות

| שדה | ערך |
|-----|-----|
| **Routes** | `PUT/DELETE /api/campaigns/<id>`, `POST/DELETE /api/playbook` |
| **קובץ** | `routes/campaigns.py` |
| **סטטוס** | Open |

**תיקון:** `@admin_required` או creator-only ל-delete/edit.

---

### QA-006 — Ingest API חלש מ-UI Submit

| שדה | ערך |
|-----|-----|
| **Route** | `POST /api/v1/ioc` |
| **סטטוס** | Open |

**חסר לעומת `/api/submit-ioc`:** sanity checks, tag governance, comment sanitization.

**תיקון:** שימוש באותה pipeline function כ-submit-ioc.

---

### QA-007 — סיסמת Admin — מינימום 4 תווים

| שדה | ערך |
|-----|-----|
| **Route** | `POST /api/admin/users` |
| **סטטוס** | Open |

**סתירה:** `change-password` דורש 8+; יצירת user דורשת 4+.

**תיקון:** min 8 בכל המקומות + complexity policy אחיד.

---

### QA-008 — Avatar upload ללא הגבלת גודל

| שדה | ערך |
|-----|-----|
| **Routes** | `POST /api/profile/avatar`, `POST /api/admin/users/<id>/avatar` |
| **סטטוס** | Open |

**תיקון:** cap (למשל 2MB) + resize server-side.

---

### QA-009 — IOC value > 1024 chars

| שדה | ערך |
|-----|-----|
| **קובץ** | `utils/validation.py` |
| **DB** | `String(1024)` |
| **סטטוס** | Open |

**תיקון:** pre-validation עם הודעת 400 ברורה לפני DB insert.

---

### QA-010 — Tag governance bypass

| שדה | ערך |
|-----|-----|
| **פונקציה** | `_validate_tags_or_reject()` |
| **סטטוס** | Open |

**בעיה:** `except Exception: return tags_list, None` — tags עוברים בלי enforcement.

**תיקון:** log + reject או fallback ל-tags מותרים בלבד.

---

### QA-011 — DEV_MODE backdoor

| שדה | ערך |
|-----|-----|
| **קובץ** | `routes/auth.py` |
| **סטטוס** | Open |

**בעיה:** `devuser`/`dev` → admin auto-login כש-`DEV_MODE=1`.

**תיקון:** ודא `DEV_MODE=0` ב-production; health check מדווח על DEV_MODE.

---

### QA-012 — Submit-staging — 0 items ללא feedback

| שדה | ערך |
|-----|-----|
| **Route** | `/api/submit-staging` |
| **סטטוס** | Open |

**תיקון:** אם 0 שורות approved — החזר 400 עם הודעה "No valid IOCs to submit".

---

## 4.3 P2 — בינוני

| ID | ממצא | תיקון מוצע |
|----|------|-------------|
| QA-013 | Paste preview — אין cap על אורך text | max chars (למשל 500KB) |
| QA-014 | Notes — אין בדיקת IOC קיים | verify IOC exists before save |
| QA-015 | Revoke reason — אין max length | max 500 chars |
| QA-016 | Admin API 500 → HTTP 200 + success:false | החזר status code נכון |
| QA-017 | הודעות allowlist שונות submit vs ingest | unify error messages |
| QA-018 | YARA resubmit — campaign name לא קיים | return 400 / warning |
| QA-019 | Ticker messages — text ריק | require non-empty |
| QA-020 | אין rate limiting על login | flask-limiter / fail2ban |
| QA-021 | Profile כפול modal + page | consolidate או sync |
| QA-022 | Bulk SMART grouping לא ב-UI | tooltip / docs |

---

## 4.4 P3 — נמוך / Polish

- הודעות שגיאה לא עקביות (`JSON body required` vs constants)
- `#yaraTableFilter`, `#playbookSearch` — client-only filter, לא API
- Built-in playbook edits — local only (toast), לא persisted
- Champs inactive user — **תוקן** (מוסתר מ-ladder) — לבדוק regression
- Login placeholder — **תוקן** ל-`username`
- Inbox YARA rejection reason + resubmit — **תוקן** — לבדוק E2E

---

## 5. מה עובד טוב ✅

| תחום | הערכה |
|------|--------|
| Validation IOC | IP/Domain/Hash/Email/URL — regex + refanger + sanity |
| Staging workflow | Preview → edit → approve |
| YARA syntax | 512KB cap + `yara.compile` לפני save |
| Auth stack | Flask-Login, LDAP, must_change_password, session timeout |
| API errors | רוב `/api/*` מחזירים JSON עקבי |
| Audit | CEF log + IOC history |
| Tag governance | allowed + suggest + admin approve (כשפועל) |
| File uploads YARA/Campaign | caps/sanitize קיימים |
| Health check | `/health` — DB, LDAP, DXL |
| Unit tests | validation, tags, allowlist, integrations, champs SMART |

---

## 6. כיסוי בדיקות אוטומטיות

### קיים ב-`tests/`

| קובץ | תחום |
|------|------|
| `test_validation.py` | IOC validation |
| `test_refanger.py` | refanger |
| `test_tags.py` | tag governance |
| `test_allowlist.py` | allowlist |
| `test_yara_rejection.py` | YARA reject flow |
| `test_champs_smart_scoring.py` | SMART #8 scoring |
| Integration tests | Cortex, Trellix, MISP, וכו' |

### חסר (מומלץ להוסיף)

- [ ] E2E Flask test client
- [ ] Auth / authorization (view-yara, revoke, edit)
- [ ] Login redirect validation
- [ ] Admin settings save
- [ ] Frontend JS (אופציונלי — Playwright)

**הרצה:**
```bash
cd /path/to/ioc_submission
python -m pytest tests/ -v --tb=short
```

---

## 7. תוכנית תיקונים (עדיפות)

| # | ממצא | פעולה | מאמץ | סטטוס |
|---|------|--------|------|--------|
| 1 | QA-001 | `@login_required` על view-yara | נמוך | Open |
| 2 | QA-002 | Authorization revoke/edit IOC | בינוני | Open |
| 3 | QA-003 | Validate `next` redirect | נמוך | Open |
| 4 | QA-005 | Admin/creator על campaign/playbook | בינוני | Open |
| 5 | QA-006 | יישור ingest API עם submit-ioc | בינוני | Open |
| 6 | QA-007 | Password policy אחיד (min 8) | נמוך | Open |
| 7 | QA-009 | IOC value length pre-check | נמוך | Open |
| 8 | QA-008 | Avatar size cap | נמוך | Open |
| 9 | QA-012 | Staging error when 0 items | נמוך | Open |
| 10 | — | pytest suite ל-P0/P1 | בינוני | Open |

---

## 8. Checklist ידני לשרת

### 8.1 Auth & Users

- [ ] Login תקין / שגוי / user deactivated
- [ ] `must_change_password` — חסימת navigation
- [ ] Session timeout (Admin settings)
- [ ] LDAP test + login
- [ ] Deactivate user → לא ב-Champs, לא login
- [ ] `/login?next=//evil.com` — **QA-003**

### 8.2 IOC Submit

- [ ] Single: IP, Domain, Hash, Email, URL — valid + invalid
- [ ] Private IP — two-step confirm
- [ ] Allowlist block
- [ ] Duplicate IOC
- [ ] Tags restricted → suggest flow
- [ ] CSV 100+ rows, metadata זהה (SMART grouping)
- [ ] CSV עם שורות invalid — staging feedback (**QA-012**)
- [ ] Assign to analyst אחר

### 8.3 Search & Investigate

- [ ] Search filters + pagination + export CSV
- [ ] Edit comment/tags/campaign
- [ ] Delete with reason — Champs SMART points
- [ ] Add note (2000 chars max)
- [ ] Delete IOC של משתמש אחר — **QA-002**

### 8.4 YARA

- [ ] Upload `.yar` valid/invalid syntax
- [ ] Pending → Admin approve/reject → Inbox notification
- [ ] Resubmit rejected + dismiss notification
- [ ] `GET /api/view-yara/...` ללא login — **QA-001**
- [ ] Admin delete with reason

### 8.5 Campaigns & Playbook

- [ ] Create + link IOC + reference image
- [ ] Delete campaign — **QA-005**
- [ ] Playbook add/edit/delete — **QA-005**

### 8.6 Champs (SMART #8)

- [ ] Scoring method 8 פעיל
- [ ] Single IOC, bulk group, YARA pending=10, deletion tiers
- [ ] Deactivated user hidden from ladder (regression)
- [ ] Team goal + ticker (admin)

### 8.7 Admin

- [ ] Create user (password policy — **QA-007**)
- [ ] Settings save + LDAP/MISP/TAXII test
- [ ] Allowlist edit + reload
- [ ] Integrations hub — test connection per vendor
- [ ] Certificate upload
- [ ] Scoring method switch

### 8.8 Inbox

- [ ] YARA approved → notification + dismiss
- [ ] YARA rejected → reason + "Edit & resubmit" link
- [ ] TAG suggest approved/rejected

---

## 9. שינויים שבוצעו לפני הדוח (לבדיקת regression)

| תחום | שינוי | קבצים |
|------|--------|-------|
| Inbox YARA | סיבת דחייה + קישור resubmit | `app.js`, `yara.js`, `yara.py`, i18n |
| Champs SMART #8 | effort scoring, deletion tiers, bulk grouping | `champs.py`, routes |
| Champs inactive | מוסתר מ-ladder, data נשמר | `routes/champs.py` |
| Login | placeholder → `username` | `templates/login.html` |

---

## 10. היסטוריית עדכונים

| תאריך | שינוי |
|-------|--------|
| 2026-06-21 | יצירת דוח ראשוני — Code Review + מיפוי Inputs |

---

*עדכן סטטוסים בטבלה (סעיף 4) ככל שמתקנים ממצאים.*
