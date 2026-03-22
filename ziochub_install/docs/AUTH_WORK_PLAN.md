# Authentication & Authorization - Work Plan

## Context & Constraints

- **Target OS:** Linux (project runs on Linux; development may be on Windows)
- **Offline support:** Must work when:
  - No network access
  - No central AD
  - Optional local AD/LDAP
  - Fully standalone (no LDAP)
- **Audit:** Each action tied to a user; read-only for anonymous

---

## Phase 1: Core Data Model & Local Auth

| # | Task | Details |
|---|------|---------|
| 1.1 | Add `users` table | `id`, `username` (unique), `password_hash` (nullable for LDAP), `source` (local/ldap), `is_admin`, `is_active`, `created_at`, `updated_at` |
| 1.2 | Add `user_id` FK to IOCs | Add `user_id` column (FK to `users.id`) to main `iocs` table; required immediately for Champ Analysis. See migration steps below. |
| 1.3 | Add `user_profiles` table | `user_id` (FK), `display_name`, `role_description`, `avatar_path`, `email` (optional) |
| 1.4 | Add `user_sessions` table | `user_id`, `login_at`, `logout_at`, `ip_address` - for analytics and audit |
| 1.5 | Create local admin user | Implement inside app startup logic (e.g. `_init_db`); auto-create initial admin (e.g. `admin`) with hashed password on first run - works out-of-the-box in offline setups |
| 1.6 | Implement local login | Login form, password verification with `werkzeug.security`, session creation |
| 1.7 | Add Flask-Login (or manual sessions) | `current_user`, `login_required`, `logout_user` |
| 1.8 | Protect write endpoints | Apply decorator to all routes that modify data (submit, delete, update, exclude, etc.) |
| 1.9 | Read-only for anonymous | Unauthenticated users can view Live Stats, Feed Pulse, Search, etc., but not change data |

### Task 1.2 - Migration Steps for `user_id` on IOCs

When implementing the `user_id` column on the `iocs` table, follow this order to avoid data loss and constraint violations:

1. **Create the `admin` user first** (complete Task 1.5 before or as part of the same migration).
2. **Add the `user_id` column** to `iocs` as nullable initially (e.g. `ALTER TABLE iocs ADD COLUMN user_id INTEGER REFERENCES users(id)`).
3. **Update all existing IOCs** to `user_id = 1` (the default admin): `UPDATE iocs SET user_id = 1 WHERE user_id IS NULL`.
4. **Apply the NOT NULL constraint.** With SQLite, `ALTER TABLE ADD CONSTRAINT` is limited; use one of:
   - **Batch migration pattern:** Create new table with `user_id INTEGER NOT NULL`, copy data, drop old table, rename new table.
   - Or keep `user_id` nullable in schema but enforce in application (less ideal for referential integrity).

---

## Phase 2: Admin Panel & Local Users

| # | Task | Details |
|---|------|---------|
| 2.1 | Admin-only decorator | `@admin_required` (requires `is_admin=True`) |
| 2.2 | Admin settings page | Route `/admin/settings` - configurable system settings |
| 2.3 | Local user management | Admin can create/edit/deactivate local users; set `source=local`, store password hash |
| 2.4 | User list UI | Table of users (username, source, is_admin, last login, actions) |
| 2.5 | Config storage | Store auth config (LDAP enabled, LDAP URL, etc.) in DB or config file |

---

## Phase 3: LDAP/AD Integration (Optional, Offline-aware)

| # | Task | Details |
|---|------|---------|
| 3.1 | Add `ldap3` | Add to `requirements.txt` |
| 3.2 | LDAP config | `LDAP_ENABLED`, `LDAP_URL`, `LDAP_BASE_DN`, `LDAP_BIND_DN` (service account), `LDAP_BIND_PASSWORD`, `LDAP_USER_FILTER` |
| 3.3 | Dev: use `MOCK_SYNC` | When LDAP unavailable (dev/offline), use ldap3 `MOCK_SYNC` strategy to simulate LDAP responses for development and testing |
| 3.4 | LDAP auth flow | On login: if LDAP enabled and reachable → try LDAP bind; on success, create/update user in `users` with `source=ldap`. Retrieve user's `displayName` (or `cn`) attribute from AD and sync to `user_profiles.display_name` - ensures Leaderboard shows real names |
| 3.5 | Fallback to local auth | If LDAP disabled/unreachable → fall back to local users only |
| 3.6 | Local AD support | Same LDAP flow for local AD (different `LDAP_URL`, e.g. `ldap://local-dc.internal`) |
| 3.7 | Health check for LDAP | Endpoint or status flag: LDAP reachable or not (for UI/operational visibility) |

---

## Phase 4: User Profiles & Avatar

| # | Task | Details |
|---|------|---------|
| 4.1 | Profile edit page | User can edit `display_name`, `role_description` |
| 4.2 | Avatar upload | Save to `static/avatars/{user_id}.{ext}`, store path in `user_profiles` |
| 4.3 | Profile display | Show avatar + display name in header/sidebar |
| 4.4 | Default avatar | Placeholder when no avatar |

---

## Phase 5: Session & Activity Analytics

| # | Task | Details |
|---|------|---------|
| 5.1 | Log sessions | On login: insert into `user_sessions` |
| 5.2 | Log logout / expiry | On logout or session end: update `logout_at` |
| 5.3 | Enrich audit log | Ensure `audit_log` includes `user_id` for actions |
| 5.4 | Analyst stats API | Endpoint for login frequency, last seen, contribution count per user |
| 5.5 | Analyst stats UI | Optional dashboard or section for analyst activity |

---

## Phase 6: Offline & Dev Mode

| # | Task | Details |
|---|------|---------|
| 6.1 | Config flags | `AUTH_MODE`: `local_only` / `ldap` / `ldap_with_local_fallback` |
| 6.2 | Dev mode | When `FLASK_DEBUG` or `DEV_MODE=1`, allow auto-login or test user for development |
| 6.3 | Graceful LDAP failure | No crash when LDAP unavailable; fall back to local users and log warning |
| 6.4 | Documentation | Document how to run fully offline (no AD, no LDAP) |

---

## Implementation Order (Summary)

```
Phase 1 (Core)     → Phase 2 (Admin) → Phase 3 (LDAP) → Phase 4 (Profiles) → Phase 5 (Analytics) → Phase 6 (Offline/Dev)
     ↓                    ↓                  ↓
  Foundation          User mgmt        Optional, with fallback
```

---

## File Structure (Proposed)

```
app.py                  # Auth routes, decorators, LDAP logic
models.py               # User, UserProfile, UserSession
utils/auth.py           # LDAP bind, local auth helpers
utils/decorators.py     # @login_required, @admin_required
templates/login.html
templates/admin/
  - settings.html
  - users.html
static/avatars/         # User avatars
config.py               # LDAP_ENABLED, LDAP_URL, AUTH_MODE, etc.
```

---

## Testing Scenarios

1. **Offline, local only:** No LDAP; admin + local users work
2. **Offline, local AD:** LDAP URL points to local DC; auth via LDAP
3. **Online, central AD:** Same LDAP flow with central AD URL
4. **LDAP down:** Fallback to local users; no crash
5. **Anonymous:** Can browse; cannot submit/update/delete
