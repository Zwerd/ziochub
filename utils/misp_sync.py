"""
MISP Integration - pull IOC attributes from a MISP instance into ThreatGate.

Requires: pymisp (pip install pymisp)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

from utils.validation import validate_ioc

_log = logging.getLogger('threatgate.misp')

PYMISP_AVAILABLE = False
try:
    from pymisp import PyMISP
    PYMISP_AVAILABLE = True
except ImportError:
    PyMISP = None  # type: ignore

# MISP attribute type -> ThreatGate IOC type
MISP_TYPE_MAP = {
    'ip-src': 'IP',
    'ip-dst': 'IP',
    'ip-src|port': 'IP',
    'ip-dst|port': 'IP',
    'domain': 'Domain',
    'hostname': 'Domain',
    'url': 'URL',
    'uri': 'URL',
    'link': 'URL',
    'md5': 'Hash',
    'sha1': 'Hash',
    'sha256': 'Hash',
    'sha512': 'Hash',
    'ssdeep': 'Hash',
    'imphash': 'Hash',
    'email-src': 'Email',
    'email-dst': 'Email',
    'email': 'Email',
}

SUPPORTED_MISP_TYPES = list(MISP_TYPE_MAP.keys())


def _connection_error_message(exc: Exception, url: str) -> str:
    """Turn connection/SSL errors into a user-friendly message with hints."""
    msg = str(exc).strip()[:300]
    hint = (
        ' Check: (1) MISP URL must include the port if not 443, e.g. https://127.0.0.1:8443 ; '
        '(2) MISP service is running ; '
        '(3) for self-signed certificates, disable "Verify SSL" in settings.'
    )
    err_lower = msg.lower()
    if 'max retries' in err_lower or 'connection' in err_lower or 'refused' in err_lower or 'timed out' in err_lower:
        return msg + hint
    if 'certificate' in err_lower or 'ssl' in err_lower or 'tls' in err_lower:
        return msg + ' Try disabling "Verify SSL" for self-signed certificates.' + hint
    return msg


def test_connection(url: str, api_key: str, verify_ssl: bool = False) -> tuple[bool, str]:
    """Test connectivity to a MISP instance. Returns (ok, message)."""
    if not PYMISP_AVAILABLE:
        return False, 'pymisp is not installed'
    if not url or not api_key:
        return False, 'MISP URL and API key are required'
    try:
        misp = PyMISP(url.rstrip('/'), api_key, ssl=verify_ssl, timeout=15)
        ver = misp.misp_instance_version
        if ver and isinstance(ver, dict) and 'version' in ver:
            return True, f"Connected - MISP v{ver['version']}"
        return True, 'Connected'
    except Exception as e:
        _log.warning('MISP test_connection failed: %s', e)
        return False, _connection_error_message(e, url)


def _clean_ip_port(value: str) -> str:
    """Extract IP from 'ip|port' composite attributes."""
    if '|' in value:
        return value.split('|')[0].strip()
    return value.strip()


def fetch_attributes(
    url: str,
    api_key: str,
    verify_ssl: bool = False,
    last_days: int = 30,
    filter_tags: str = '',
    filter_types: str = '',
    published_only: bool = True,
    limit: int = 5000,
) -> tuple[list[dict], str | None]:
    """
    Fetch IOC attributes from MISP.
    Returns (list_of_ioc_dicts, error_message_or_None).
    Each dict: {value, tg_type, misp_type, event_id, event_info, comment}
    """
    if not PYMISP_AVAILABLE:
        return [], 'pymisp is not installed'
    if not url or not api_key:
        return [], 'MISP URL and API key are required'

    try:
        misp = PyMISP(url.rstrip('/'), api_key, ssl=verify_ssl, timeout=30)
    except Exception as e:
        return [], 'Connection failed: ' + _connection_error_message(e, url)

    type_list = [t.strip() for t in filter_types.split(',') if t.strip()] if filter_types else SUPPORTED_MISP_TYPES
    type_list = [t for t in type_list if t in MISP_TYPE_MAP]
    if not type_list:
        return [], 'No valid MISP attribute types to fetch'

    tag_list = [t.strip() for t in filter_tags.split(',') if t.strip()] if filter_tags else None

    since = (datetime.now(timezone.utc) - timedelta(days=max(last_days, 1))).strftime('%Y-%m-%d')

    search_kwargs = {
        'type_attribute': type_list,
        'date_from': since,
        'limit': limit,
        'to_ids': True,
        'pythonify': True,
    }
    if published_only:
        search_kwargs['published'] = True
    if tag_list:
        search_kwargs['tags'] = tag_list

    try:
        response = misp.search('attributes', **search_kwargs)
    except Exception as e:
        return [], f'MISP search failed: {e}'

    if isinstance(response, dict) and 'errors' in response:
        return [], f"MISP API error: {response['errors']}"

    attrs = response if isinstance(response, list) else []
    # Collect with timestamp for sorting – keep latest per (type, value)
    with_ts = []
    for attr in attrs:
        misp_type = getattr(attr, 'type', '') if hasattr(attr, 'type') else (attr.get('type', '') if isinstance(attr, dict) else '')
        value = getattr(attr, 'value', '') if hasattr(attr, 'value') else (attr.get('value', '') if isinstance(attr, dict) else '')
        if not value or not misp_type:
            continue

        tg_type = MISP_TYPE_MAP.get(misp_type)
        if not tg_type:
            continue

        if misp_type in ('ip-src|port', 'ip-dst|port'):
            value = _clean_ip_port(value)

        value = value.strip()
        ts = getattr(attr, 'timestamp', 0) if hasattr(attr, 'timestamp') else (attr.get('timestamp', 0) if isinstance(attr, dict) else 0)
        try:
            ts = int(ts) if ts else 0
        except (TypeError, ValueError):
            ts = 0

        event_id = ''
        event_info = ''
        comment = ''
        if hasattr(attr, 'Event') and attr.Event:
            event_id = str(getattr(attr.Event, 'id', ''))
            event_info = getattr(attr.Event, 'info', '') or ''
        elif hasattr(attr, 'event_id'):
            event_id = str(attr.event_id)
        elif isinstance(attr, dict):
            event_id = str(attr.get('event_id', ''))

        if hasattr(attr, 'comment'):
            comment = attr.comment or ''
        elif isinstance(attr, dict):
            comment = attr.get('comment', '') or ''

        with_ts.append((ts, {
            'value': value,
            'tg_type': tg_type,
            'misp_type': misp_type,
            'event_id': event_id,
            'event_info': event_info[:200],
            'comment': comment[:500],
        }))

    # Sort by timestamp descending (newest first); then dedupe by (tg_type, value) so latest wins
    with_ts.sort(key=lambda x: x[0], reverse=True)
    seen = set()
    results = []
    for _ts, item in with_ts:
        dedup_key = (item['tg_type'], item['value'].lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        results.append(item)

    return results, None


def sync_to_db(
    attributes: list[dict],
    misp_user_id: int,
    misp_username: str,
    default_ttl_days: int | None = None,
) -> dict:
    """
    Insert MISP attributes into ThreatGate DB.
    Must be called within Flask app context.
    Returns summary: {added, skipped, errors}
    """
    from extensions import db
    from models import IOC, IocHistory
    from sqlalchemy import func

    added = 0
    skipped = 0
    errors = 0

    exp_date = None
    if default_ttl_days and default_ttl_days > 0:
        exp_date = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=default_ttl_days)

    invalid = 0
    for attr in attributes:
        value = attr['value']
        tg_type = attr['tg_type']
        event_id = attr.get('event_id', '')
        event_info = attr.get('event_info', '')
        attr_comment = attr.get('comment', '')

        if not validate_ioc(value, tg_type):
            _log.debug('MISP sync skipping invalid %s value: %s', tg_type, value[:80])
            invalid += 1
            continue

        existing = IOC.query.filter(
            IOC.type == tg_type,
            func.lower(IOC.value) == value.lower(),
        ).first()
        if existing:
            skipped += 1
            continue

        comment_parts = []
        if event_info:
            comment_parts.append(f'[MISP] {event_info}')
        if attr_comment:
            comment_parts.append(attr_comment)
        comment = ' | '.join(comment_parts) if comment_parts else '[MISP Import]'

        try:
            ioc = IOC(
                type=tg_type,
                value=value,
                analyst=misp_username,
                ticket_id=f'MISP-{event_id}' if event_id else None,
                comment=comment[:1000],
                expiration_date=exp_date,
                user_id=misp_user_id,
            )
            db.session.add(ioc)
            db.session.add(IocHistory(
                ioc_type=tg_type,
                ioc_value=value,
                event_type='created',
                username=misp_username,
                payload=json.dumps({'source': 'misp', 'misp_event': event_id}),
            ))
            added += 1
        except Exception as e:
            _log.warning('MISP sync insert error for %s: %s', value[:80], e)
            errors += 1

    if added > 0:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            _log.exception('MISP sync commit failed: %s', e)
            return {'added': 0, 'skipped': skipped, 'errors': added + errors, 'error': str(e)}

    return {'added': added, 'skipped': skipped, 'errors': errors, 'invalid': invalid}


def ensure_misp_user(username: str = 'misp_sync') -> tuple[int, str]:
    """
    Ensure a local user for MISP sync exists. Returns (user_id, username).
    Must be called within Flask app context.
    """
    from extensions import db
    from models import User, UserProfile

    user = User.query.filter_by(username=username).first()
    if user:
        if user.source != 'system':
            user.source = 'system'
            db.session.commit()
        return user.id, user.username

    user = User(
        username=username,
        password_hash=None,
        source='system',
        is_admin=False,
        is_active=True,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(UserProfile(user_id=user.id, display_name='MISP Sync'))
    db.session.commit()
    _log.info('Created MISP sync user: %s (id=%d)', username, user.id)
    return user.id, user.username


_LOCK_KEY = 'misp_sync_lock'
_LOCK_TIMEOUT_SECONDS = 600  # 10 min - stale lock auto-expires


def _acquire_lock() -> bool:
    """Set a DB-based lock flag. Returns True if lock acquired."""
    from extensions import db
    from models import SystemSetting
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row = SystemSetting.query.filter_by(key=_LOCK_KEY).first()
    if row and row.value:
        try:
            lock_time = datetime.fromisoformat(row.value)
            if (now - lock_time).total_seconds() < _LOCK_TIMEOUT_SECONDS:
                return False
        except (ValueError, TypeError):
            pass
    if row:
        row.value = now.isoformat()
    else:
        db.session.add(SystemSetting(key=_LOCK_KEY, value=now.isoformat()))
    db.session.commit()
    return True


def _release_lock():
    """Clear the sync lock."""
    from extensions import db
    from models import SystemSetting
    row = SystemSetting.query.filter_by(key=_LOCK_KEY).first()
    if row:
        row.value = ''
        db.session.commit()


def run_sync(settings: dict) -> dict:
    """
    Full sync pipeline: fetch from MISP -> insert into ThreatGate.
    `settings` can be raw (from DB); they are normalized via misp_settings.
    Must be called within Flask app context.
    Uses a DB-based lock to prevent concurrent syncs.
    Returns summary dict.
    """
    from misp_settings import normalize_sync_settings
    settings = normalize_sync_settings(settings)

    if not _acquire_lock():
        return {'success': False, 'error': 'Another sync is already running. Try again later.'}
    try:
        url = (settings.get('misp_url') or '').strip()
        api_key = (settings.get('misp_api_key') or '').strip()
        if not url or not api_key:
            return {'success': False, 'error': 'MISP URL and API key not configured'}

        verify_ssl = (settings.get('misp_verify_ssl') or 'false').lower() == 'true'
        try:
            last_days = int(settings.get('misp_last_days') or 30)
        except (ValueError, TypeError):
            last_days = 30
        filter_tags = settings.get('misp_filter_tags') or ''
        filter_types = settings.get('misp_filter_types') or ''
        published_only = (settings.get('misp_published_only') or 'true').lower() != 'false'

        default_ttl = None
        ttl_raw = (settings.get('misp_default_ttl') or '').strip().lower()
        if ttl_raw and ttl_raw != 'permanent' and ttl_raw != '0':
            try:
                default_ttl = int(ttl_raw)
            except (ValueError, TypeError):
                pass

        sync_user = (settings.get('misp_sync_user') or 'misp_sync').strip()
        user_id, username = ensure_misp_user(sync_user)

        attrs, err = fetch_attributes(
            url=url,
            api_key=api_key,
            verify_ssl=verify_ssl,
            last_days=last_days,
            filter_tags=filter_tags,
            filter_types=filter_types,
            published_only=published_only,
        )
        if err:
            return {'success': False, 'error': err, 'fetched': 0}

        result = sync_to_db(attrs, user_id, username, default_ttl)
        result['success'] = True
        result['fetched'] = len(attrs)
        return result
    finally:
        _release_lock()
