"""
Generic failed outbound integration retry queue (IOC + YARA push vendors).

Each vendor stores settings as ``{vendor}_retry_enabled``, ``{vendor}_retry_interval_minutes``,
``{vendor}_retry_max_attempts``, and ``{vendor}_retry_queue_json`` in ``system_settings``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from extensions import db
from models import SystemSetting, _utcnow

logger = logging.getLogger(__name__)

MAX_QUEUE_ITEMS = 300

TRANSIENT_ERROR_MARKERS = (
    'temporary failure in name resolution',
    'name or service not known',
    'nodename nor servname provided',
    'network is unreachable',
    'connection timed out',
    'timed out',
    'connection reset',
    'connection refused',
    'tls error',
    'ssl:',
    'network error',
    'missing reply object',
    'empty or non-json response',
    'http 0',
    'login failed',
    'connect to broker',
    'waf_blocked',
    'waf_or_gateway_blocked',
    'gateway_error',
    'rate_limited',
)

IOC_VENDORS = frozenset({
    'cortex_xdr',
    'google_secops',
    'netskope',
    'esa',
    'ioc_http',
    'misp_push',
    'dxl',
})

YARA_VENDORS = frozenset({
    'yara_http',
    'trellix_ex',
    'trellix_cms',
    'trellix_nx',
})

ALL_RETRY_VENDORS = tuple(sorted(IOC_VENDORS | YARA_VENDORS))

_NON_RETRIABLE_EXACT = frozenset({
    'disabled',
    'invalid_context',
    'missing_config',
    'missing_type_or_value',
    'remove_missing_value',
    'skipped (disabled)',
    'skipped_incomplete_data_table_config',
    'skipped_incomplete_config',
    'pymisp is not installed',
    'empty ioc value',
    'unsupported ioc type for misp',
})

_NON_RETRIABLE_PREFIXES = (
    'skip_',
    'skip_action_',
)


def integration_is_retriable_failure(message: str) -> bool:
    m = (message or '').strip().lower()
    if not m:
        return False
    if m in _NON_RETRIABLE_EXACT:
        return False
    if any(m.startswith(p) for p in _NON_RETRIABLE_PREFIXES):
        return False
    return any(marker in m for marker in TRANSIENT_ERROR_MARKERS)


def _queue_storage_key(vendor: str) -> str:
    return f'{vendor}_retry_queue_json'


def _item_key(vendor: str, payload: dict[str, Any]) -> str:
    if vendor in YARA_VENDORS:
        kind = (str(payload.get('kind') or 'push')).strip().lower()
        filename = (str(payload.get('filename') or '')).strip().lower()
        return f'{kind}|{filename}'
    action = (str(payload.get('action') or 'create')).strip().lower()
    typ = (str(payload.get('type') or payload.get('ioc_type') or '')).strip().lower()
    value = (str(payload.get('value') or '')).strip().lower()
    return f'{action}|{typ}|{value}'


def _parse_queue(raw: str) -> list[dict[str, Any]]:
    if not raw or not isinstance(raw, str):
        return []
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        payload = item.get('payload') if isinstance(item.get('payload'), dict) else item.get('ioc')
        if isinstance(payload, dict):
            item = dict(item)
            item['payload'] = payload
            out.append(item)
    return out


def _save_queue(vendor: str, items: list[dict[str, Any]]) -> None:
    key = _queue_storage_key(vendor)
    val = json.dumps(items[:MAX_QUEUE_ITEMS], ensure_ascii=False)
    s = SystemSetting.query.filter_by(key=key).first()
    if s:
        s.value = val
    else:
        db.session.add(SystemSetting(key=key, value=val))
    db.session.commit()


def get_integration_retry_queue(vendor: str, get_setting: Callable[[str, str], str]) -> list[dict[str, Any]]:
    raw = (get_setting(_queue_storage_key(vendor), '') or '').strip()
    return _parse_queue(raw)


def integration_retry_interval_minutes(vendor: str, get_setting: Callable[[str, str], str]) -> int:
    raw = (get_setting(f'{vendor}_retry_interval_minutes', '15') or '15').strip()
    try:
        n = int(raw)
    except ValueError:
        n = 15
    return max(1, min(1440, n))


def integration_retry_max_attempts(vendor: str, get_setting: Callable[[str, str], str]) -> int:
    """
    Max attempts for a failed push: immediate in-request retries (e.g. Cortex HTTP)
    and scheduled queue retries share this per-vendor limit from Admin.
    """
    raw = (get_setting(f'{vendor}_retry_max_attempts', '3') or '3').strip()
    try:
        n = int(raw)
    except ValueError:
        n = 3
    return max(1, min(50, n))


def integration_retry_enabled(vendor: str, get_setting: Callable[[str, str], str]) -> bool:
    return (get_setting(f'{vendor}_retry_enabled', 'true') or 'true').strip().lower() in (
        'true', '1', 'yes',
    )


def enqueue_integration_retry(
    vendor: str,
    payload: dict[str, Any],
    error_message: str,
    *,
    get_setting: Callable[[str, str], str],
) -> None:
    if vendor not in ALL_RETRY_VENDORS:
        return
    if not isinstance(payload, dict):
        return
    if not integration_is_retriable_failure(error_message):
        return
    if not integration_retry_enabled(vendor, get_setting):
        return

    if vendor in IOC_VENDORS:
        if not (str(payload.get('value') or '')).strip():
            return
    else:
        if not (str(payload.get('filename') or '')).strip():
            return

    try:
        now = _utcnow()
        interval = integration_retry_interval_minutes(vendor, get_setting)
        key = _item_key(vendor, payload)
        queue = get_integration_retry_queue(vendor, get_setting)
        updated = False
        for item in queue:
            if item.get('key') == key:
                item['payload'] = dict(payload)
                item['last_error'] = (str(error_message or '')[:500])
                item['attempts'] = int(item.get('attempts') or 0)
                item['updated_at'] = now.isoformat()
                item['next_retry_at'] = (now + timedelta(minutes=interval)).isoformat()
                updated = True
                break
        if not updated:
            queue.append({
                'key': key,
                'payload': dict(payload),
                'failed_at': now.isoformat(),
                'updated_at': now.isoformat(),
                'next_retry_at': (now + timedelta(minutes=interval)).isoformat(),
                'attempts': 0,
                'last_error': (str(error_message or '')[:500]),
            })
        if len(queue) > MAX_QUEUE_ITEMS:
            queue = queue[-MAX_QUEUE_ITEMS:]
        _save_queue(vendor, queue)
    except Exception:
        logger.exception('enqueue_integration_retry failed vendor=%s', vendor)
        try:
            db.session.rollback()
        except Exception:
            pass


def enqueue_integration_retries(
    vendor: str,
    failures: list[tuple[dict[str, Any], str]],
    *,
    get_setting: Callable[[str, str], str],
) -> None:
    for payload, msg in failures or []:
        if isinstance(payload, dict):
            enqueue_integration_retry(vendor, payload, msg, get_setting=get_setting)


def process_integration_retry_queue(
    vendor: str,
    get_setting: Callable[[str, str], str],
    *,
    force: bool = False,
) -> dict[str, Any]:
    from utils.integration_retry_handlers import dispatch_integration_retry_push

    if vendor not in ALL_RETRY_VENDORS:
        return {'processed': 0, 'succeeded': 0, 'failed': 0, 'remaining': 0, 'error': 'unknown_vendor'}

    if not integration_retry_enabled(vendor, get_setting):
        return {'processed': 0, 'succeeded': 0, 'failed': 0, 'remaining': 0, 'skipped': 'disabled'}

    queue = get_integration_retry_queue(vendor, get_setting)
    if not queue:
        return {'processed': 0, 'succeeded': 0, 'failed': 0, 'remaining': 0, 'results': []}

    now = _utcnow()
    interval = integration_retry_interval_minutes(vendor, get_setting)
    max_attempts = integration_retry_max_attempts(vendor, get_setting)
    due: list[dict[str, Any]] = []
    not_due: list[dict[str, Any]] = []
    for item in queue:
        if force:
            due.append(item)
            continue
        nra = item.get('next_retry_at')
        try:
            if nra:
                dt = datetime.fromisoformat(str(nra).replace('Z', '+00:00'))
                if dt.tzinfo is not None:
                    dt = dt.replace(tzinfo=None)
                if dt <= now:
                    due.append(item)
                else:
                    not_due.append(item)
            else:
                due.append(item)
        except Exception:
            due.append(item)

    if not due:
        return {
            'processed': 0,
            'succeeded': 0,
            'failed': 0,
            'remaining': len(queue),
            'results': [],
            'message': 'No items due for retry yet.',
        }

    results: list[dict[str, Any]] = []
    succeeded = 0
    failed = 0
    abandoned = 0
    remaining_queue = list(not_due)

    for item in due:
        payload = item.get('payload') if isinstance(item.get('payload'), dict) else {}
        key = item.get('key') or _item_key(vendor, payload)
        attempts = int(item.get('attempts') or 0) + 1
        ok, msg = dispatch_integration_retry_push(vendor, payload, from_retry=True)
        entry = {
            'key': key,
            'success': ok,
            'message': (msg or '')[:240],
            'attempts': attempts,
        }
        if vendor in YARA_VENDORS:
            entry['filename'] = (payload.get('filename') or '')[:128]
            entry['kind'] = payload.get('kind')
        else:
            entry['value'] = (payload.get('value') or '')[:128]
            entry['action'] = payload.get('action')
            entry['type'] = payload.get('type') or payload.get('ioc_type')
        results.append(entry)
        if ok:
            succeeded += 1
            continue
        failed += 1
        if integration_is_retriable_failure(msg) and attempts < max_attempts:
            item['attempts'] = attempts
            item['last_error'] = (msg or '')[:500]
            item['updated_at'] = now.isoformat()
            item['next_retry_at'] = (now + timedelta(minutes=interval)).isoformat()
            remaining_queue.append(item)
        else:
            abandoned += 1
            if integration_is_retriable_failure(msg) and attempts >= max_attempts:
                logger.warning(
                    'Integration retry giving up vendor=%s key=%s after %s attempts (max=%s): %s',
                    vendor, key, attempts, max_attempts, msg,
                )
            else:
                logger.warning(
                    'Integration retry giving up vendor=%s key=%s: %s',
                    vendor, key, msg,
                )

    try:
        _save_queue(vendor, remaining_queue)
    except Exception:
        logger.exception('process_integration_retry_queue save failed vendor=%s', vendor)
        try:
            db.session.rollback()
        except Exception:
            pass

    return {
        'processed': len(due),
        'succeeded': succeeded,
        'failed': failed,
        'abandoned': abandoned,
        'remaining': len(remaining_queue),
        'max_attempts': max_attempts,
        'results': results,
    }


def process_all_integration_retry_queues(
    get_setting: Callable[[str, str], str],
    *,
    force: bool = False,
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for vendor in ALL_RETRY_VENDORS:
        if not integration_retry_enabled(vendor, get_setting):
            continue
        summary = process_integration_retry_queue(vendor, get_setting, force=force)
        if summary.get('processed'):
            out[vendor] = summary
    return out
