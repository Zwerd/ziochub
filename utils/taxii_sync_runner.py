"""
Shared TAXII 2.1 inbound pull runner (systemd timer + in-app scheduler).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from utils.misp_sync_runner import SCHEDULER_WAKE_SEC, normalize_misp_pull_interval

logger = logging.getLogger(__name__)

TAXII_PULL_INTERVAL_DEFAULT = 60


def normalize_taxii_pull_interval(raw: Optional[str]) -> int:
    return normalize_misp_pull_interval(raw)


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


def taxii_sync_due(get_setting: Callable[[str, str], str], *, now: Optional[datetime] = None) -> tuple[bool, str]:
    if (get_setting('taxii_pull_enabled', 'false') or 'false').strip().lower() != 'true':
        return False, 'disabled'
    url = (get_setting('taxii_discovery_url', '') or '').strip()
    api_key = (get_setting('taxii_api_key', '') or '').strip()
    user = (get_setting('taxii_username', '') or '').strip()
    pwd = (get_setting('taxii_password', '') or '').strip()
    if not url or (not api_key and not (user and pwd)):
        return False, 'missing_config'

    pull_interval_min = normalize_taxii_pull_interval(
        get_setting('taxii_pull_interval', str(TAXII_PULL_INTERVAL_DEFAULT))
    )
    last_dt = _parse_last_sync(get_setting('taxii_last_sync', ''))
    now_dt = now or datetime.now(timezone.utc).replace(tzinfo=None)
    if last_dt is not None:
        if now_dt - last_dt < timedelta(minutes=pull_interval_min):
            return False, 'interval_not_elapsed'
    return True, 'due'


def next_taxii_pull_at(get_setting: Callable[[str, str], str], *, now: Optional[datetime] = None) -> Optional[str]:
    last_dt = _parse_last_sync(get_setting('taxii_last_sync', ''))
    if last_dt is None:
        return None
    interval = normalize_taxii_pull_interval(
        get_setting('taxii_pull_interval', str(TAXII_PULL_INTERVAL_DEFAULT))
    )
    return (last_dt + timedelta(minutes=interval)).isoformat()


def run_taxii_sync_if_due(
    get_setting: Callable[[str, str], str],
    set_setting: Callable[[str, str], None],
    *,
    force: bool = False,
    log_fn: Callable[[str], None] = logger.info,
) -> dict[str, Any]:
    if not force:
        due, reason = taxii_sync_due(get_setting)
        if not due:
            return {'success': True, 'skipped': True, 'skip_reason': reason}

    settings = {
        'taxii_discovery_url': get_setting('taxii_discovery_url', ''),
        'taxii_api_root_id': get_setting('taxii_api_root_id', ''),
        'taxii_collection_id': get_setting('taxii_collection_id', ''),
        'taxii_username': get_setting('taxii_username', ''),
        'taxii_password': get_setting('taxii_password', ''),
        'taxii_api_key': get_setting('taxii_api_key', ''),
        'taxii_verify_ssl': get_setting('taxii_verify_ssl', 'false'),
        'taxii_last_days': get_setting('taxii_last_days', '30'),
        'taxii_default_ttl': get_setting('taxii_default_ttl', 'permanent'),
        'taxii_sync_user': get_setting('taxii_sync_user', 'taxii_sync'),
        'taxii_skip_revoked': get_setting('taxii_skip_revoked', 'true'),
        'taxii_last_sync': get_setting('taxii_last_sync', ''),
    }

    from utils.taxii_sync import run_sync

    log_fn('[taxii-sync] Starting pull from remote TAXII')
    result = run_sync(settings)
    now_str = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    set_setting('taxii_last_sync', now_str)
    set_setting('taxii_last_sync_result', json.dumps(result)[:1000])

    if result.get('success'):
        log_fn(
            '[taxii-sync] OK fetched=%s added=%s skipped=%s invalid=%s errors=%s'
            % (
                result.get('fetched', 0),
                result.get('added', 0),
                result.get('skipped', 0),
                result.get('invalid', 0),
                result.get('errors', 0),
            )
        )
    else:
        log_fn('[taxii-sync] FAIL %s' % (result.get('error') or 'unknown'))
    result['skipped'] = False
    return result


def _lock_path(data_dir: str) -> str:
    return os.path.join(data_dir, '.taxii_sync.lock')


def run_taxii_sync_if_due_with_lock(app, *, force: bool = False) -> dict[str, Any]:
    import app as app_module

    data_dir = getattr(app_module, 'DATA_DIR', None) or os.path.join(app.root_path, 'data')
    os.makedirs(data_dir, exist_ok=True)
    lock_file = _lock_path(data_dir)
    fh = None
    try:
        try:
            import fcntl

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

            return run_taxii_sync_if_due(_get, _set, force=force)
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
