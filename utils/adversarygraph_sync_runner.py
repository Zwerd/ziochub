"""
Shared AdversaryGraph inbound sync runner (systemd timer + in-app scheduler).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from utils.misp_sync_runner import SCHEDULER_WAKE_SEC, normalize_misp_pull_interval

logger = logging.getLogger(__name__)

ADVERSARYGRAPH_PULL_INTERVAL_DEFAULT = 60


def normalize_adversarygraph_pull_interval(raw: Optional[str]) -> int:
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


def adversarygraph_sync_due(get_setting: Callable[[str, str], str], *, now: Optional[datetime] = None) -> tuple[bool, str]:
    if (get_setting('adversarygraph_enabled', 'false') or 'false').strip().lower() != 'true':
        return False, 'disabled'
    url = (get_setting('adversarygraph_url', '') or '').strip()
    if not url:
        return False, 'missing_config'

    pull_interval_min = normalize_adversarygraph_pull_interval(
        get_setting('adversarygraph_pull_interval', str(ADVERSARYGRAPH_PULL_INTERVAL_DEFAULT))
    )
    last_dt = _parse_last_sync(get_setting('adversarygraph_last_sync', ''))
    now_dt = now or datetime.now(timezone.utc).replace(tzinfo=None)
    if last_dt is not None:
        if now_dt - last_dt < timedelta(minutes=pull_interval_min):
            return False, 'interval_not_elapsed'
    return True, 'due'


def next_adversarygraph_pull_at(get_setting: Callable[[str, str], str], *, now: Optional[datetime] = None) -> Optional[str]:
    """ISO timestamp when the next automatic pull is expected."""
    last_dt = _parse_last_sync(get_setting('adversarygraph_last_sync', ''))
    if last_dt is None:
        return None
    interval = normalize_adversarygraph_pull_interval(
        get_setting('adversarygraph_pull_interval', str(ADVERSARYGRAPH_PULL_INTERVAL_DEFAULT))
    )
    return (last_dt + timedelta(minutes=interval)).isoformat()


def run_adversarygraph_sync_if_due(
    get_setting: Callable[[str, str], str],
    set_setting: Callable[[str, str], None],
    *,
    force: bool = False,
    log_fn: Callable[[str], None] = logger.info,
) -> dict[str, Any]:
    if not force:
        due, reason = adversarygraph_sync_due(get_setting)
        if not due:
            return {'success': True, 'skipped': True, 'skip_reason': reason}

    settings = {
        'adversarygraph_url': get_setting('adversarygraph_url', ''),
        'adversarygraph_verify_ssl': get_setting('adversarygraph_verify_ssl', 'false'),
        'adversarygraph_auth_user': get_setting('adversarygraph_auth_user', ''),
        'adversarygraph_auth_roles': get_setting('adversarygraph_auth_roles', 'analyst'),
        'adversarygraph_last_days': get_setting('adversarygraph_last_days', '30'),
        'adversarygraph_filter_types': get_setting('adversarygraph_filter_types', ''),
        'adversarygraph_filter_sources': get_setting('adversarygraph_filter_sources', ''),
        'adversarygraph_pull_yara': get_setting('adversarygraph_pull_yara', 'true'),
        'adversarygraph_default_ttl': get_setting('adversarygraph_default_ttl', 'permanent'),
        'adversarygraph_sync_user': get_setting('adversarygraph_sync_user', 'adversarygraph_sync'),
    }

    from utils.adversarygraph_sync import run_sync

    log_fn('[adversarygraph-sync] Starting pull from AdversaryGraph')
    result = run_sync(settings, get_setting_fn=get_setting)
    now_str = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    set_setting('adversarygraph_last_sync', now_str)
    set_setting('adversarygraph_last_sync_result', json.dumps(result)[:1000])

    if result.get('success'):
        log_fn(
            '[adversarygraph-sync] OK ioc_fetched=%s ioc_added=%s yara_added=%s'
            % (
                result.get('fetched', 0),
                result.get('added', 0),
                result.get('yara_added', 0),
            )
        )
    else:
        log_fn('[adversarygraph-sync] FAIL %s' % (result.get('error') or 'unknown'))
    if isinstance(result.get('skipped'), (int, float)):
        result['duplicates_skipped'] = int(result['skipped'])
    result['skipped'] = False
    if not force:
        from utils.audit_events import audit_sync_result
        audit_sync_result('adversarygraph_sync_auto', result)
    return result


def _lock_path(data_dir: str) -> str:
    return os.path.join(data_dir, '.adversarygraph_sync.lock')


def run_adversarygraph_sync_if_due_with_lock(app, *, force: bool = False) -> dict[str, Any]:
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

            return run_adversarygraph_sync_if_due(_get, _set, force=force)
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
