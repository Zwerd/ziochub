"""
When to run pull schedulers inside Gunicorn workers vs systemd timers.

Production (ziochub.service) sets ZIOCHUB_USE_SYSTEMD_SYNC=1 so MISP/TAXII pull
jobs run once via ziochub-misp-sync.timer / ziochub-taxii-sync.timer — not in every
web worker (avoids duplicate sync threads and worker load under Gunicorn).

Lab / ``python3 app.py`` keeps in-app schedulers unless the env var is set.
"""
from __future__ import annotations

import os


def _env_truthy(name: str) -> bool | None:
    raw = (os.environ.get(name) or '').strip().lower()
    if raw in ('1', 'true', 'yes', 'on'):
        return True
    if raw in ('0', 'false', 'no', 'off'):
        return False
    return None


def use_systemd_sync_jobs() -> bool:
    """True when pull sync should run via systemd timers only (not in Gunicorn workers)."""
    explicit = _env_truthy('ZIOCHUB_USE_SYSTEMD_SYNC')
    if explicit is not None:
        return explicit
    return False


def inapp_misp_sync_enabled() -> bool:
    override = _env_truthy('ZIOCHUB_INAPP_MISP_SYNC')
    if override is not None:
        return override
    return not use_systemd_sync_jobs()


def inapp_taxii_sync_enabled() -> bool:
    override = _env_truthy('ZIOCHUB_INAPP_TAXII_SYNC')
    if override is not None:
        return override
    return not use_systemd_sync_jobs()
