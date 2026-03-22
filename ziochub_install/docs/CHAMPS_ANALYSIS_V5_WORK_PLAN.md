# Champs Analysis 5.0 - תוכנית עבודה

> מסמך מקביל: [CHAMPS_ANALYSIS_V5_SPEC.md](./CHAMPS_ANALYSIS_V5_SPEC.md)

---

## סדר ביצוע מומלץ

```
Phase 0 (Foundation) → Phase 1 (Scoring) → Phase 2 (Ladder) → Phase 3 (Spotlight) → Phase 4 (Team HUD) → Phase 5 (Ticker)
        ↓                      ↓                   ↓                    ↓                    ↓
   DB + Avatars          ניקוד חדש           לידרבורד חדש         כרטיס אנליסט          יעד צוותי          טיקר חי
```

---

## Phase 0: תשתית (Foundation)

**מטרה:** הכנת DB, assets ואפשרויות טכניות לכל השלבים הבאים.

| # | משימה | פרטים |
|---|-------|--------|
| 0.1 | טבלת `team_goals` | `id`, `title`, `target_value`, `current_value`, `unit`, `period` (weekly/monthly), `is_active`, `created_at`, `updated_at` |
| 0.2 | טבלת `activity_events` | `id`, `event_type`, `user_id`, `payload` (JSON), `created_at` - לוג לטיקר |
| 0.3 | טבלת `champ_rank_snapshots` (אופציונלי) | `id`, `user_id`, `rank`, `score`, `snapshot_date` - לשימור מגמות יומיות |
| 0.4 | תיקיית `static/avatars/default/` | 20 תמונות Sci-Fi גנריות (placeholder או assets קיימים) |
| 0.5 | Endpoint `/api/champs/config` | החזרת תצורת ניקוד (נקודות לפי סוג) - לקריאה מצד הלקוח |

**תלויות:** אין.  
**קבצים:** `models.py`, `app.py` (migrations / init), `static/avatars/default/`

---

## Phase 1: לוגיקת ניקוד חדשה (Scoring)

**מטרה:** מעבר מניקוד פשוט (1 IOC, 5x YARA) לניקוד לפי הספק.

| # | משימה | פרטים |
|---|-------|--------|
| 1.1 | פונקציית `compute_ioc_points(ioc)` | IP/Domain רגיל=10, IP+Campaign=15, Hash רגיל=10, Hash+Campaign=15, YARA=50 |
| 1.2 | פונקציית `compute_deletion_points()` | מחיקת מזהה פג תוקף = 5 נקודות |
| 1.3 | חישוב בונוס רצף (Streak) | 3 ימים רצופים של פעילות → +10% לניקוד היומי |
| 1.4 | עדכון `get_analyst_stats` / API חדש | שימוש בפונקציות הניקוד החדשות במקום ספירה פשוטה |
| 1.5 | שמירת snapshot יומי (אופציונלי) | Job או on-demand - שמירת rank/score ל-`champ_rank_snapshots` לצורך מגמות |

**תלויות:** Phase 0 (אם משתמשים ב-snapshots).  
**קבצים:** `app.py`, `utils/champs.py` (חדש)

---

## Phase 2: הלידרבורד הדינמי (The Ladder)

**מטרה:** החלפת הלידרבורד הנוכחי בלידרבורד עם avatars, מדליות ומגמות.

| # | משימה | פרטים |
|---|-------|--------|
| 2.1 | Endpoint `GET /api/champs/leaderboard` | רשימת אנליסטים: rank, username, display_name, score, avatar_path, trend (▲+2 / ▼-1 / —), medal |
| 2.2 | חישוב trend | השוואת rank היום ל-rank אתמול (מ-`champ_rank_snapshots` או חישוב on-the-fly) |
| 2.3 | Layout חדש ל-tab Champs | סרגל שמאל ~25% - רשימת אנליסטים עם avatar, שם, מדליה, trend |
| 2.4 | CSS: עיצוב הלידרבורד | Avatars בעיגול, הדגשת top 3, אנימציית hover |
| 2.5 | מיפוי user_id ↔ analyst | שימוש ב-`User` + `UserProfile` (display_name, avatar) - תאימות ל-IOC.analyst / YaraRule.analyst |

**תלויות:** Phase 0, Phase 1.  
**קבצים:** `app.py`, `templates/index.html` (tab-champs), `static/css/style.css`

---

## Phase 3: כרטיס השחקן (Analyst Spotlight)

**מטרה:** כרטיס מרכזי שנפתח בלחיצה על אנליסט.

| # | משימה | פרטים |
|---|-------|--------|
| 3.1 | Endpoint `GET /api/champs/analyst/<user_id>` | XP, level, nickname, activity_per_day (30 יום), badges |
| 3.2 | לוגיקת כינוי (Nickname) | IPs→Network Hunter, Hash→Malware Slayer, YARA→Code Breaker (לפי סוג המזהים הכי נפוץ) |
| 3.3 | לוגיקת Level/XP | X נקודות = Level Y (טבלת סף קבועה, למשל 100/250/500/1000) |
| 3.4 | לוגיקת Badges | On Fire (5 ימים רצוף), Night Owl (22-04), Rare Find, Janitor |
| 3.5 | גרף השוואה | Chart.js: קו האנליסט vs קו ממוצע צוותי (30 יום) |
| 3.6 | UI: אזור Spotlight | מרכז המסך, כרטיס עם שם+כינוי, XP bar, גרף, שורת badges |
| 3.7 | אינטגרציה: לחיצה על אנליסט ב-Ladder | טעינת Spotlight ומילוי הנתונים |

**תלויות:** Phase 2.  
**קבצים:** `app.py`, `templates/index.html`, `static/js/` (או inline ב-index)

---

## Phase 4: המשימה המשותפת (Team HUD)

**מטרה:** בר התקדמות ליעד צוותי בראש המסך.

| # | משימה | פרטים |
|---|-------|--------|
| 4.1 | לוגיקת `current_value` | חישוב אוטומטי לפי סוג היעד: IOC count, YARA count, deletions וכו' |
| 4.2 | Endpoint `GET /api/champs/team-goal` | יעד פעיל: title, target_value, current_value, percent |
| 4.3 | Endpoints Admin: `GET/POST /api/champs/team-goal` | יצירה/עדכון יעד (admin only) |
| 4.4 | UI: Team HUD | פס עליון - בר התקדמות זוהר, טקסט היעד, אחוז |
| 4.5 | אפקט ויזואלי | מילוי הבר עם אנימציה / ניצוץ (CSS או JS קל) |

**תלויות:** Phase 0.  
**קבצים:** `app.py`, `templates/index.html`, `templates/admin/` (אם יש דף הגדרות יעדים)

---

## Phase 5: הטיקר החי (News Ticker)

**מטרה:** פס תחתון עם אירועים חיים.

| # | משימה | פרטים |
|---|-------|--------|
| 5.1 | שמירת אירועים ל-`activity_events` | בעת submit IOC, YARA, מחיקה, שינוי דירוג - הוספת רשומה |
| 5.2 | Endpoint `GET /api/champs/ticker` | אירועים אחרונים (limit 20), מעוצבים כהודעות |
| 5.3 | UI: פס טיקר | תחתית המסך, טקסט רץ (marquee או JS), עדכון כל דקה |
| 5.4 | פורמט הודעות | "X עקף את Y ועלה למקום Z" / "X העלה חוק YARA" / "היעד הצוותי ב-80%" |

**תלויות:** Phase 0 (activity_events), Phase 2 (דירוג), Phase 4 (יעד).  
**קבצים:** `app.py`, `templates/index.html`

---

## Phase 6: ליטושים וסגירת פערים

**מטרה:** עקביות, ביצועים ותיעוד.

| # | משימה | פרטים |
|---|-------|--------|
| 6.1 | התאמת RTL / עברית | טקסטים, כיווניות, i18n |
| 6.2 | Polling/Refresh | רענון אוטומטי כל X דקות (configurable) |
| 6.3 | הסרת/ארכוב קוד ישן | Threat Velocity, Analyst Activity - החלטה אם לשמור או להחליף |
| 6.4 | תיעוד | עדכון README ו-i18n keys |

---

## סיכום תלויות

| Phase | תלוי ב- | זמן משוער (הערכה) |
|-------|---------|---------------------|
| 0 | - | 1-2 שעות |
| 1 | 0 | 2-3 שעות |
| 2 | 0, 1 | 2-3 שעות |
| 3 | 2 | 3-4 שעות |
| 4 | 0 | 2 שעות |
| 5 | 0, 2, 4 | 2 שעות |
| 6 | 1-5 | 1 שעה |

**סה"כ:** ~15-17 שעות עבודה משוערות.

---

## צעד ראשון למימוש

לאחר אישור התוכנית - להתחיל ב-**Phase 0** (תשתית DB + avatars).
