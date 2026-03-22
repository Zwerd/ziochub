"""
ZIoCHub configuration from environment variables.

All paths and secrets can be overridden via env. If not set, the application
uses defaults relative to the application directory.

Phase 6: AUTH_MODE, DEV_MODE for offline and development.
"""
import os

# Base directory for data (optional). If not set, app uses <app_dir>/data.
DATA_DIR = os.environ.get("ZIOCHUB_DATA_DIR", "").strip() or None

# Auth mode override (Phase 6.1): local_only | ldap | ldap_with_local_fallback
# Can also be set via Admin Settings (system_settings table).
AUTH_MODE = os.environ.get("AUTH_MODE", "").strip() or None

# Dev mode (Phase 6.2): when 1 or true, enables dev auto-login and LDAP mock.
# Security: Do not enable in production. App logs a startup warning when DEV_MODE is True,
# and an error when DEV_MODE is True and FLASK_ENV or ZIOCHUB_ENV is set to "production".
DEV_MODE = os.environ.get("DEV_MODE", "").strip().lower() in ("1", "true", "yes")

# Flask secret key. In production, set SECRET_KEY explicitly.
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip() or None

# Max upload size in bytes (default 16MB).
_MAX_MB = os.environ.get("ZIOCHUB_MAX_CONTENT_MB", "16").strip()
try:
    MAX_CONTENT_LENGTH = int(_MAX_MB or "16") * 1024 * 1024
except (ValueError, TypeError):
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

# Database path. If DATA_DIR is set, use DATA_DIR/ziochub.db; otherwise app computes it.
DB_PATH = None
if DATA_DIR:
    DB_PATH = os.path.join(DATA_DIR, "ziochub.db")
