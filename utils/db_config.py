"""
Database configuration: PostgreSQL (production) with optional legacy SQLite path for migration.
"""
from __future__ import annotations

import os
from urllib.parse import quote_plus


def data_dir(default: str) -> str:
    raw = (os.environ.get('ZIOCHUB_DATA_DIR') or '').strip()
    return raw or default


def legacy_sqlite_path(data_directory: str) -> str:
    return os.path.join(data_directory, 'ziochub.db')


def load_ziochub_env_file(data_directory: str, *, override: bool = False) -> bool:
    """
    Load ``data/ziochub.env`` into ``os.environ`` (systemd EnvironmentFile format).

    Returns True if the file was read. Does not override existing vars unless ``override=True``.
    """
    env_path = os.path.join(data_directory, 'ziochub.env')
    if not os.path.isfile(env_path):
        return False
    with open(env_path, encoding='utf-8', errors='replace') as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('export '):
                line = line[7:].strip()
            if '=' not in line:
                continue
            key, _, val = line.partition('=')
            key = key.strip()
            if not key:
                continue
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if not override and key in os.environ:
                continue
            os.environ[key] = val
    return True


def ensure_postgresql_env_loaded(data_directory: str) -> str | None:
    """
    Load ziochub.env when PostgreSQL vars are missing. Returns env file path or None.
    """
    if (os.environ.get('ZIOCHUB_DATABASE_URL') or '').strip():
        return os.path.join(data_directory, 'ziochub.env')
    if os.environ.get('ZIOCHUB_PG_PASSWORD'):
        return os.path.join(data_directory, 'ziochub.env')
    path = os.path.join(data_directory, 'ziochub.env')
    if load_ziochub_env_file(data_directory):
        return path
    return None


def build_database_url(*, data_directory: str) -> tuple[str, str]:
    """
    Return (sqlalchemy_uri, backend_label).

    Loads ``data/ziochub.env`` when PostgreSQL vars are not already in the environment
    (same behaviour as systemd ``EnvironmentFile``), so ``python3 app.py`` on port 5000
    uses the same PostgreSQL as the production service without manual ``source``.

    Priority: env vars → ziochub.env → legacy ``data/ziochub.db`` (SQLite upgrades only).
    Unmigrated installs with only ``ziochub.db`` and no ``ziochub.env`` keep using SQLite.
    """
    ensure_postgresql_env_loaded(data_directory)
    explicit = (os.environ.get('ZIOCHUB_DATABASE_URL') or '').strip()
    if explicit:
        return explicit, _backend_from_url(explicit)

    host = (os.environ.get('ZIOCHUB_PG_HOST') or '127.0.0.1').strip()
    port = (os.environ.get('ZIOCHUB_PG_PORT') or '5432').strip()
    dbname = (os.environ.get('ZIOCHUB_PG_DB') or 'ziochub').strip()
    user = (os.environ.get('ZIOCHUB_PG_USER') or 'ziochub').strip()
    password = os.environ.get('ZIOCHUB_PG_PASSWORD') or ''

    if user and dbname and password:
        safe_user = quote_plus(user)
        safe_pass = quote_plus(password)
        uri = f'postgresql+psycopg2://{safe_user}:{safe_pass}@{host}:{port}/{dbname}'
        return uri, 'postgresql'

    sqlite_path = legacy_sqlite_path(data_directory)
    if os.path.isfile(sqlite_path):
        return 'sqlite:///' + sqlite_path.replace('\\', '/'), 'sqlite'

    raise RuntimeError(
        'PostgreSQL is not configured. Set ZIOCHUB_DATABASE_URL or ZIOCHUB_PG_* in '
        f'{os.path.join(data_directory, "ziochub.env")} (run setup.sh).'
    )


def _backend_from_url(url: str) -> str:
    lower = (url or '').lower()
    if lower.startswith('postgresql') or lower.startswith('postgres'):
        return 'postgresql'
    if lower.startswith('sqlite'):
        return 'sqlite'
    return 'unknown'


def is_sqlite_engine(engine) -> bool:
    try:
        return engine.dialect.name == 'sqlite'
    except Exception:
        return False


def is_postgresql_engine(engine) -> bool:
    try:
        return engine.dialect.name == 'postgresql'
    except Exception:
        return False
