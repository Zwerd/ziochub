# ייעול ניקוד ודף Champs Analysis

מסמך זה מתאר שלבים לייעול הלוגיקה של חישוב הניקוד והדף Champs Analysis, מבלי לשבור את האפליקציה.  
המטרה: להפסיק עבודה כפולה (עדכון ChampScore שלא נקרא בתצוגה) ולהישען על invalidation של cache בלבד.

**סטטוס:** כל שלושת השלבים יושמו. Champs Analysis עובד כרגיל ויעיל יותר (ראה אימות ויעילות למטה).

---

## רקע קצר

- **Leaderboard** נבנה תמיד מ־`compute_analyst_scores()` (ואגרגציה ב-DB) - לא קורא מ־ChampScore.
- **ChampScore** (לפני הייעול) התעדכן בהזנה (IOC/YARA) ובזמן בניית ה-leaderboard (backfill), אך **אין קוד שקורא ממנו** לתצוגה.
- **Trend (▲/▼)** ו-**Ticker** נשענים על **ChampRankSnapshot**, שמתמלא מה־`rows` המחושבים - לא מ־ChampScore.

לאחר הייעול: לא כותבים יותר ל־ChampScore; רק invalidation של cache אחרי הזנה.

---

## שלב 1: פישוט `refresh_champ_score_for_user` (app.py) ✅ בוצע

**מטרה:** להשאיר רק ביטול cache כדי שהתצוגה תתעדכן, בלי לקרוא ל־`refresh_champ_score`.

**מיקום:** `app.py` - פונקציה `refresh_champ_score_for_user(user_id)`.

**שינוי מוצע:**

1. להסיר את הקריאה ל־`refresh_champ_score` ואת ה־`_commit_with_retry()` הקשור אליה.
2. להשאיר (או להוסיף) רק:
   - `delete_cached(f'champs_leaderboard_{method}')` - כדי שבטעינה הבאה של Champs ירוץ שוב `compute_analyst_scores` והדירוג יהיה מעודכן.
   - (אופציונלי) `delete_cached(f'champs_analyst_{user_id}_{method}')` - כדי שהמשתמש שעכשיו העלה נתונים יפתח את ה-Spotlight שלו, הוא יראה עדכון מיד (בלי להמתין ל־TTL של 5 דקות).

**מה לא לשנות:**  
כל המקומות שקוראים ל־`refresh_champ_score_for_user` נשארים כפי שהם (אחרי submit IOC, YARA, staging וכו') - משנים רק את תוכן הפונקציה.

---

## שלב 2: הסרת Backfill של ChampScore ב־Leaderboard (routes/champs.py) ✅ בוצע

**מטרה:** להפסיק לכתוב ל־ChampScore בזמן בניית ה-leaderboard.

**מיקום:** `routes/champs.py` - בתוך `get_champs_leaderboard()`, אחרי  
`rows = compute_analyst_scores(...)`.

**שינוי מוצע:**

1. להסיר את כל הבלוק `try: ... except: ...` שעובר על `rows`, מעדכן/יוצר רשומות ב־ChampScore, ועושה commit (או rollback בשגיאה).
2. להשאיר ללא שינוי:
   - `compute_analyst_scores`
   - `save_daily_rank_snapshots(..., rows=rows)` - ה-trend וה-ticker נשענים על ChampRankSnapshot שמתמלא מה־`rows` המחושבים.
   - בניית רשימת `leaderboard` וה־return.

**מה לא לשבור:**  
התצוגה לא קוראת מ־ChampScore; ה-trend וה-ticker ממשיכים לעבוד כי הם מקבלים את ה־`rows` ו־ChampRankSnapshot לא תלוי ב־ChampScore.

---

## שלב 3 (אופציונלי): ניקוי קוד מת ✅ בוצע

**מטרה:** להקטין בלבול ולמנוע שימוש עתידי בשכבת ChampScore שלא בשימוש.

1. **`_leaderboard_rows_from_champ_scores`** ב־`routes/champs.py` - הוסרה; הוסר גם ה-import של ChampScore מאותו קובץ.
2. **`refresh_champ_score`** ב־`utils/champs.py` - הוסרה לגמרי. הוסר ה-import שלה מ־`routes/champs.py` וה-import של ChampScore מ־`app.py`.

---

## מה לא לגעת בו (כדי לא לשבור)

| רכיב | סיבה |
|------|------|
| **ChampRankSnapshot** | שומר snapshots יומיים של דירוג/ניקוד; משמש ל-trend ו-rank change events. ממולא מה־`rows` המחושבים ב-leaderboard. |
| **מודל ChampScore והטבלה** | אפשר להשאיר (פשוט לא לכתוב אליה). הסרת הטבלה/מודל דורשת מיגרציה ובדיקה שאין קוד שכותב/קורא - עדיף בשלב מאוחר אם בכלל. |
| **כל מקום שקורא ל־`refresh_champ_score_for_user`** | לא לשנות חתימות או להסיר קריאות; רק את המימוש של הפונקציה (שלב 1). |

---

## סיכום שלבים

| שלב | פעולה | סטטוס |
|-----|--------|--------|
| **1** | ב־`app.py`: ב־`refresh_champ_score_for_user` להשאיר רק invalidation של cache (leaderboard + analyst detail). | ✅ בוצע |
| **2** | ב־`routes/champs.py`: להסיר את הבלוק שכותב ל־ChampScore אחרי `compute_analyst_scores`. | ✅ בוצע |
| **3** | להסיר `_leaderboard_rows_from_champ_scores`, `refresh_champ_score`, ו-imports של ChampScore/refresh_champ_score. | ✅ בוצע |

---

## אימות: Champs Analysis עובד תקין אחרי הייעול

נבדק שהזרימה המלאה לא נפגעה:

| רכיב | איך הוא עובד עכשיו |
|------|---------------------|
| **Leaderboard** | `get_champs_leaderboard`: cache → אם חסר, `compute_analyst_scores()` → `save_daily_rank_snapshots(rows=rows)` → `get_rank_change_events(rows)` → בניית רשימת leaderboard מ־`rows` → set_cached → return. אין שימוש ב־ChampScore. |
| **Trend (▲/▼)** | `get_rank_trend(db, ChampRankSnapshot, uid, rank)` - קורא מ־ChampRankSnapshot שמתמלא ב־`save_daily_rank_snapshots(rows=rows)`. לא תלוי ב־ChampScore. |
| **Ticker (rank change)** | אירועים נוצרים מ־`get_rank_change_events(..., rows)` ו־ChampRankSnapshot. לא תלוי ב־ChampScore. |
| **פרט אנליסט (Spotlight)** | `get_champs_analyst` → `get_analyst_detail()` → `compute_analyst_scores()` + שאילתות aggregation. Cache מפתח `champs_analyst_{user_id}_{method}` מתבטל ב־`refresh_champ_score_for_user(user_id)` אחרי הזנה. |
| **אחרי הזנת IOC/YARA** | `refresh_champ_score_for_user(user_id)` רק קורא ל־`delete_cached(leaderboard)` ו־`delete_cached(analyst_{user_id})`. הטעינה הבאה של Champs/Spotlight תחשב מחדש מהטבלאות. |

המסקנה: התצוגה והעדכונים נשענים רק על `compute_analyst_scores`, aggregation ב-DB ו-cache. ChampScore לא נדרש לתפקוד.

---

## יעילות: מה השתפר

| נקודה | לפני | אחרי |
|--------|------|------|
| **בכל הזנת IOC/YARA** | קריאה ל־`refresh_champ_score`: הרבה שאילתות aggregation + כתיבת שורה ל־ChampScore + commit. | רק 2 קריאות ל־`delete_cached` (זיכרון). אין גישה ל-DB. |
| **בכל טעינת leaderboard (cache miss)** | `compute_analyst_scores` + לולאה על כל האנליסטים: get/create ChampScore, עדכון שדות, commit (ו־rollback בשגיאה). | `compute_analyst_scores` + `save_daily_rank_snapshots(rows)` + בניית הרשימה. אין כתיבה ל־ChampScore. |
| **קוד** | פונקציות מתות: `_leaderboard_rows_from_champ_scores`, `refresh_champ_score`. | הוסרו; פחות קוד וברור יותר. |

ה-scale (כולל מעל מיליון IOCs) נשמר - התצוגה נשענת על aggregation ב-DB ו-cache כמו קודם; הורדנו רק עבודה מיותרת (כתיבה ל־ChampScore וחישוב per-user בהזנה).

---

## לאחר הייעול

- הלוגיקה יעילה יותר (אין עדכוני ChampScore מיותרים).
- האפליקציה ממשיכה לעבוד כמו לפני (אימות למעלה).
- ה-scale (כולל מעל מיליון IOCs) נשמר - התצוגה נשענת על aggregation ב-DB ו-cache.
