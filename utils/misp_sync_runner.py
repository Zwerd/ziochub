"""
Shared MISP inbound sync runner.

Used by:
- ``misp_sync_job.py`` (systemd timer, every 5 min)
- ``utils.misp_sync_scheduler`` (in-app background thread when Gunicorn/Flask runs)
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

MISP_PULL_INTERVAL_PRESETS = (10, 30, 60, 120, 360, 1440)
MISP_PULL_INTERVAL_DEFAULT = 60
MISP_PULL_INTERVAL_MIN = 5
MISP_PULL_INTERVAL_MAX = 1440
SCHEDULER_WAKE_SEC = 300  # check every 5 minutes (matches systemd timer)


def normalize_misp_pull_interval(raw: Optional[str]) -> int:
    try:
        n = int(str(raw or '').strip())
    except (TypeError, ValueError):
        n = MISP_PULL_INTERVAL_DEFAULT
    return max(MISP_PULL_INTERVAL_MIN, min(MISP_PULL_INTERVAL_MAX, n))


def _parse_last_sync(last_sync_str: str) -> Optional[datetime]:
    s = (last_sync_str or '').strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except (ValueError, TypeError):
        return None


def misp_sync_due(get_setting: Callable[[str, str], str], *, now: Optional[datetime] = None) -> tuple[bool, str]:
    """
    Return (should_run, reason).
    reason is a short code for logging/UI: disabled, missing_config, interval_not_elapsed, due.
    """
    if (get_setting('misp_enabled', 'false') or 'false').strip().lower() != 'true':
        return False, 'disabled'
    url = (get_setting('misp_url', '') or '').strip()
    api_key = (get_setting('misp_api_key', '') or '').strip()
    if not url or not api_key:
        return False, 'missing_config'

    pull_interval_min = normalize_misp_pull_interval(get_setting('misp_pull_interval', str(MISP_PULL_INTERVAL_DEFAULT)))
    last_sync_str = (get_setting('misp_last_sync', '') or '').strip()
    last_dt = _parse_last_sync(last_sync_str)
    now_dt = now or datetime.now(timezone.utc).replace(tzinfo=None)
    if last_dt is not None:
        elapsed = now_dt - last_dt
        if elapsed < timedelta(minutes=pull_interval_min):
            return False, 'interval_not_elapsed'
    return True, 'due'


def next_misp_pull_at(get_setting: Callable[[str, str], str], *, now: Optional[datetime] = None) -> Optional[str]:
    """ISO timestamp when the next automatic pull is expected (based on last sync + interval)."""
    last_dt = _parse_last_sync(get_setting('misp_last_sync', ''))
    if last_dt is None:
        return None
    interval = normalize_misp_pull_interval(get_setting('misp_pull_interval', str(MISP_PULL_INTERVAL_DEFAULT)))
    nxt = last_dt + timedelta(minutes=interval)
    return nxt.isoformat()


def run_misp_sync_if_due(
    get_setting: Callable[[str, str], str],
    set_setting: Callable[[str, str], None],
    *,
    force: bool = False,
    log_fn: Callable[[str], None] = logger.info,
) -> dict[str, Any]:
    """
    Pull IOCs from MISP when enabled and interval elapsed (or ``force=True`` for manual sync).
    Updates ``misp_last_sync`` / ``misp_last_sync_result`` on every attempt.
    """
    if not force:
        due, reason = misp_sync_due(get_setting)
        if not due:
            return {'success': True, 'skipped': True, 'skip_reason': reason}

    url = (get_setting('misp_url', '') or '').strip()
    api_key = (get_setting('misp_api_key', '') or '').strip()
    settings = {
        'misp_url': url,
        'misp_api_key': api_key,
        'misp_verify_ssl': get_setting('misp_verify_ssl', 'false'),
        'misp_last_days': get_setting('misp_last_days', '30'),
        'misp_filter_tags': get_setting('misp_filter_tags', ''),
        'misp_filter_types': get_setting('misp_filter_types', ''),
        'misp_published_only': get_setting('misp_published_only', 'true'),
        'misp_default_ttl': get_setting('misp_default_ttl', 'permanent'),
        'misp_sync_user': get_setting('misp_sync_user', 'misp_sync'),
    }

    from utils.misp_sync import run_sync

    log_fn('[misp-sync] Starting pull from MISP')
    result = run_sync(settings)
    now_str = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    set_setting('misp_last_sync', now_str)
    set_setting('misp_last_sync_result', json.dumps(result)[:1000])

    if result.get('success'):
        log_fn(
            '[misp-sync] OK fetched=%s added=%s skipped=%s invalid=%s errors=%s'
            % (
                result.get('fetched', 0),
                result.get('added', 0),
                result.get('skipped', 0),
                result.get('invalid', 0),
                result.get('errors', 0),
            )
        )
    else:
        log_fn('[misp-sync] FAIL %s' % (result.get('error') or 'unknown'))
    result['skipped'] = False
    return result


def _lock_path(data_dir: str) -> str:
    return os.path.join(data_dir, '.misp_sync.lock')


def run_misp_sync_if_due_with_lock(app, *, force: bool = False) -> dict[str, Any]:
    """File-lock wrapper so multiple Gunicorn workers do not sync in parallel."""
    import app as app_module

    data_dir = getattr(app_module, 'DATA_DIR', None) or os.path.join(app.root_path, 'data')
    os.makedirs(data_dir, exist_ok=True)
    lock_file = _lock_path(data_dir)
    fh = None
    try:
        try:
            import fcntl  # Unix only

            fh = open(lock_file, 'a', encoding='utf-8')
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            fh = None
        except OSError:
            return {'success': True, 'skipped': True, 'skip_reason': 'lock_held'}

        with app.app_context():
            def _get(key: str, default: str = '') -> str:
                return app_module._get_setting(key, default)

            def _set(key: str, value: str) -> None:
                app_module._set_setting(key, value)

            return run_misp_sync_if_due(_get, _set, force=force)
    finally:
        if fh is not None:
            try:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                fh.close()
            except Exception:
                pass
