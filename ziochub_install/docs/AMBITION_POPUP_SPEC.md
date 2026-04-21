# התראת אמביציה בכניסה (Ambition Popup)

מסמך זה מתאר רעיון לתכונה **הודעת POPUP בכניסה** - התראת אמביציה מותאמת לאנליסט בהתאם לניתוח הנתונים שלו (בדומה ל־SOC Mentorship Insights), שנותנת קו מנחה למה להתמקד עכשיו.

**סטטוס:** רעיון בלבד - אין יישום בקוד. המסמך משמש כתכנון ומפרט לעתיד.  
**שפת ההודעות:** אנגלית בלבד (כל 50 ההודעות + ברירת מחדל).

---

## 1. מטרה

- כשאנליסט **נכנס למערכת** (אחרי Login) - להציג **הודעה אחת** בסגנון POPUP.
- ההודעה תהיה **מותאמת לנתונים** שלו: Volume, Consistency, Type Diversity, Quality, Campaign, YARA, Feed Hygiene, Knowledge Sharing, Growth.
- הטון: **אמביציה ועידוד** - לא ביקורת, אלא "הצעד הבא" / "עכשיו כדאי להתמקד ב־X" / "אתה קרוב ל־Y".
- המטרה: לתת **קו מנחה מעשי** - מה כדאי לאנליסט לעשות עכשיו או השבוע.

---

## 2. חוויית משתמש (UX)

- **מתי:** בכניסה למערכת (לאחר התחברות מוצלחת), בדף הראשון שהאנליסט רואה (למשל Dashboard / Submit IOCs / הבית).
- **איך:** חלון **POPUP** (מודל) - בולט אבל לא חוסם. כפתור "הבנתי" / "סגור". אופציונלי: "אל תציג שוב היום" (למשל שמירה ב־sessionStorage או cookie ל־24 שעות).
- **תדירות:** מומלץ להציג **פעם אחת per session** או **פעם ביום** - כדי שלא להציק.
- **תוכן:** כותרת קצרה (למשל "Your focus for today") + **טקסט ההודעה** - באנגלית בלבד (משפט אחד או שניים).

---

## 3. מקור הנתונים

- אותם **סטטיסטיקות** שמנוע **SOC Mentorship Insights** משתמש בהן (`utils/mentorship.py`).
- חישוב **לאנליסט המחובר בלבד** (לא לכל הצוות): תקופה אחרונה (למשל 7/14/30 ימים) + השוואה לתקופה קודמת אם רלוונטי.
- שדות רלוונטיים (מתוך `_empty_stats` / `_bulk_analyst_stats`):
  - **Volume:** `ioc_count`, `prev_ioc_count`, `team_avg`, `active_days`, `total_days`
  - **Consistency:** `streak_days`, `max_gap_days`, `weekend_submissions`, `weekday_submissions`, `night_pct`
  - **Type Diversity:** `distinct_types`, `ip_count`, `domain_count`, `hash_count`, `url_count`, `email_count`
  - **Quality:** `with_comment_pct`, `avg_comment_len`, `max_repeated_comment`, `with_ticket_pct`
  - **Campaign:** `with_campaign_pct`, `campaigns_created`
  - **YARA:** `yara_count`, `avg_yara_quality`, `yara_rejected_count`, `yara_without_ticket`, `yara_without_campaign`
  - **Feed Hygiene:** `deletion_count`, `permanent_pct`, `stale_iocs_owned`, `anomalous_submissions`
  - **Knowledge Sharing:** `notes_count`, `with_tags_pct`, `edit_count`, `rare_find_count`
  - **Growth:** `active_badges`, `lost_badges_count`, `days_at_current_level`, `rank_change`, `days_below_team_avg`

ניתן להפעיל פונקציה דומה ל־`_bulk_analyst_stats` עבור **user_id/username אחד** ולקבל `stats` dict יחיד.

---

## 4. לוגיקת בחירת ההודעה

- **50 הודעות** שונות, כל אחת עם **תנאי** (condition) על ה־stats.
- **סדר עדיפות:** עוברים על רשימת ההודעות לפי סדר קבוע (למשל: קודם "action", אחר כך "warning", אחר כך "positive", לבסוף "neutral"). **ההודעה הראשונה** שהתנאי שלה מתקיים - היא שמוצגת.
- אם אף תנאי לא מתקיים - הודעה ברירת מחדל (באנגלית).

---

## 5. 50 הודעות האמביציה

כל שורה: מזהה, קטגוריה, תנאי (תיאור), **הודעה באנגלית בלבד** (קו מנחה).

| # | קטגוריה | תנאי (תיאור) | Message (guidance) |
|---|---------|----------------|---------------------|
| 1 | Volume | אפס IOCs בתקופה | Start fresh this week - submit your first IOC and build momentum. |
| 2 | Volume | מתחת ל־50% מממוצע הצוות | You have room to grow - try to match the team average on submissions this week. |
| 3 | Volume | מתחת ל־25% מממוצע הצוות | Submit at least one IOC today - a small step gets you back on track. |
| 4 | Volume | ירידה של 30%+ מהתקופה הקודמת | Output dipped a bit - submit one IOC today to get back into rhythm. |
| 5 | Volume | כל התרומה ביום אחד | Spreading activity across the week keeps the feed fresh and consistent. |
| 6 | Consistency | אין streak, אבל יש IOCs | Small goal: one IOC per day - build a streak and stay in the loop. |
| 7 | Consistency | פעיל בפחות מ־30% מהימים | Try to contribute on one or two more days this week - it will change the picture. |
| 8 | Consistency | פער של 5+ ימים בלי הזנות | After a break - submit one IOC today to get yourself back on track. |
| 9 | Consistency | רק בסופ״ש | Try submitting on a weekday too - daily coverage helps the team. |
| 10 | Consistency | מעל 80% מההזנות בשעות לילה | Most activity is at night - try a daytime submission to strengthen presence. |
| 11 | Type Diversity | רק סוג אחד (למשל רק IP) | This week: try another type (Domain, Hash, or URL) - diversify your skills. |
| 12 | Type Diversity | אין Hashes, יש 5+ IOCs | Add your first Hash IOC - it opens another angle in investigations. |
| 13 | Type Diversity | אין Domains | Try submitting a Domain - DNS analysis will broaden your contribution. |
| 14 | Type Diversity | אין URLs | One URL from a phishing campaign - a great direction to start. |
| 15 | Type Diversity | אין Emails | Add an Email IOC - headers and phishing are a good next step. |
| 16 | Type Diversity | 80%+ IP | Strong on IPs - add a Domain or URL this week for variety. |
| 17 | Quality | 0% הערות | Add a short comment to one IOC today - context helps the whole team. |
| 18 | Quality | פחות מ־30% עם הערות | Pick 2-3 IOCs and add a sentence of context - value goes up quickly. |
| 19 | Quality | הערות קצרות מאוד (ממוצע &lt;10 תווים) | Expand one comment this week - examples from the team can help. |
| 20 | Quality | 0% עם ticket | Link one IOC to a ticket - it helps traceability and ownership. |
| 21 | Quality | פחות מ־40% עם ticket | Small habit: add a ticket ID when you submit - it adds up. |
| 22 | Campaign | 0% מקושרים לקמפיין | Link one IOC to a campaign - it strengthens reports and analysis. |
| 23 | Campaign | פחות מ־20% לקמפיין | This week: link 2-3 IOCs to a campaign - see how it affects reports. |
| 24 | Campaign | מעולם לא יצר קמפיין | Try creating one campaign for an active investigation - it expands impact. |
| 25 | YARA | 0 YARA, 5+ IOCs | Your first YARA rule - the Playbook’s beginner guide can help. |
| 26 | YARA | YARA עם ציון איכות נמוך | Share a YARA rule with a peer - it will help you improve quality fast. |
| 27 | YARA | YARA נדחו | Feedback on rejected rules - a chance to sharpen your writing. |
| 28 | YARA | YARA בלי ticket | Add a ticket reference to your next YARA rule - helps traceability. |
| 29 | Feed Hygiene | אין מחיקות, 5+ IOCs | Spend 10 minutes - filter expired IOCs and keep the feed clean. |
| 30 | Feed Hygiene | 100% Permanent | Try a 30-90 day TTL on new IOCs - good practice for feed management. |
| 31 | Feed Hygiene | 80%+ Permanent | Most IOCs lose relevance over time - a set TTL helps the team. |
| 32 | Feed Hygiene | IOCs ישנים (180+ יום) בבעלותו | Review your older IOCs - update or close them to improve quality. |
| 33 | Knowledge | אין הערות על IOCs | Add a note to an existing IOC - it adds knowledge for the whole team. |
| 34 | Knowledge | 0% tags | One tag on your next submission - it will ease search and reports. |
| 35 | Knowledge | פחות מ־20% tags | Tagging habit - even 2-3 tagged IOCs per week make a difference. |
| 36 | Knowledge | לא ערך IOCs קיימים | Pick an old IOC and update or enrich it - review-and-enrich builds the habit. |
| 37 | Knowledge | אין rare finds | Explore less common infrastructure - a new TLD, country, or domain can be a rare find. |
| 38 | Growth | אין badges, יש IOCs | One IOC per day for 3 days - and you’ll start earning badges. |
| 39 | Growth | איבד badges | Badges will come back - start a short streak and they’ll reappear. |
| 40 | Growth | אותה רמה 30+ ימים | Try a new IOC type or a YARA rule - they can break the level plateau. |
| 41 | Growth | דירוג ירד 3+ | Rank dropped - you might be focused on a heavy case. Worth checking priorities. |
| 42 | Growth | רוב הימים מתחת לממוצע | Team average is close - one or two more active days can close the gap. |
| 43 | Positive | streak 3-4 | Nice streak - one more day and you’re On Fire. |
| 44 | Positive | streak 5+ | You’re On Fire - keep one IOC per day to maintain momentum. |
| 45 | Positive | עלית בדירוג | Rank went up - consistency pays off. Keep going in the same direction. |
| 46 | Positive | הרבה badges פעילים | Solid badges - pick one new challenge this week (type, campaign, or YARA). |
| 47 | Positive | רמה חדשה לאחרונה | You leveled up - set a small goal for the next level (IOCs or YARA). |
| 48 | Positive | תרומה מגוונת (סוגים + קמפיין) | Good variety - add comments or tags this week to strengthen quality. |
| 49 | Neutral | משתמש חדש / מעט היסטוריה | Your first submission sets the tone - pick one IOC and submit it with short context. |
| 50 | Neutral | פעילות סדירה, בלי חריגות | You’re on a steady track - pick one goal this week (tags, campaign, or YARA). |

**Default (if no condition matches):**  
"Pick one goal this week - a tag, a campaign, or YARA - and focus on it."

---

## 6. מיפוי תנאים לטכניקה

כל שורה בטבלה למעלה צריכה להיות ממופה ל־**פונקציית תנאי** שמקבלת `stats` (dict כמו ב־`_empty_stats`) ומחזירה `True`/`False`. דוגמאות:

- **#1 (אפס IOCs):** `lambda s: s['ioc_count'] == 0`
- **#6 (אין streak, יש IOCs):** `lambda s: s['streak_days'] == 0 and s['ioc_count'] > 0`
- **#43 (streak 3-4):** `lambda s: 3 <= s['streak_days'] <= 4`

סדר העדיפות בהרצה מוצע:

1. קטגוריות "action" (Volume אפס, Consistency פער גדול, וכו')
2. קטגוריות "warning" (מתחת לממוצע, ירידה, איכות נמוכה)
3. קטגוריות "info" (גיוון, קמפיין, YARA, Hygiene, Knowledge)
4. קטגוריות "Positive" (streak, עלייה בדירוג, badges)
5. קטגוריות "Neutral" וברירת מחדל

---

## 7. הערות ליישום עתידי

- **Backend:** אנדפוינט חדש, למשל `GET /api/ambition-message` (או חלק מ־`/api/me` / dashboard), שמחזיר `{ "message": "...", "message_id": 23 }`. בתוך האנדפוינט: טעינת stats לאנליסט המחובר (תקופה אחרונה), הרצת 50 התנאים לפי סדר, החזרת ההודעה הראשונה שעברה.
- **Frontend:** אחרי טעינת הדף הראשי (או לאחר login redirect) - קריאה ל־API. אם יש `message` ולא נסגר "אל תציג היום" - להציג POPUP עם הכותרת והטקסט.
- **תדירות:** שמירת "הוצגה היום" ב־sessionStorage (מפתח עם תאריך) או cookie - כך שה-POPUP יופיע לכל היותר פעם ביום (או פעם per session).
- **נגישות:** כפתור סגירה ברור, אפשרות לסגור בלחיצה מחוץ ל־POPUP או Escape.
- **שפה:** כל ההודעות באנגלית בלבד; אם בעתיד יהיה i18n - לאחסן מפתחי הודעות ולתרגם בצד הלקוח.

---

## 8. סיכום

| פריט | תיאור |
|------|--------|
| **מה** | POPUP בכניסה עם הודעת אמביציה אחת מותאמת לאנליסט |
| **מתי** | בכניסה למערכת, פעם per session או פעם ביום |
| **מקור נתונים** | סטטיסטיקות כמו ב־SOC Mentorship (לאנליסט המחובר) |
| **הודעות** | 50 הודעות + ברירת מחדל (באנגלית בלבד), עם תנאי לכל אחת |
| **טון** | עידוד, קו מנחה, "הצעד הבא" - לא ביקורת |
| **יישום** | לא מיושם - מסמך תכנון בלבד |
