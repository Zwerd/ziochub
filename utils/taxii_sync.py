"""
TAXII 2.1 client pull – fetch STIX indicators from a remote TAXII server into ZIoCHub.

Requires: requests (see requirements.txt). No separate taxii2-client package.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.auth import HTTPBasicAuth

from utils.http_identity import configure_requests_session
from utils.stix_pattern_parse import parse_indicator_pattern
from utils.validation import validate_ioc
from utils.ioc_aggregate_fields import compute_ioc_aggregate_fields

_log = logging.getLogger('ziochub.taxii')

TAXII_ACCEPT = 'application/taxii+json;version=2.1'
STIX_ACCEPT = 'application/stix+json;version=2.1'
DEFAULT_PAGE_LIMIT = 500
MAX_PAGES = 200


def _connection_error_message(exc: Exception, url: str) -> str:
    msg = str(exc).strip()[:300]
    hint = (
        ' Check: (1) discovery URL ends with /taxii2/ ; '
        '(2) credentials (Basic or Bearer API key) ; '
        '(3) for self-signed TLS, disable Verify SSL.'
    )
    err_lower = msg.lower()
    if any(x in err_lower for x in ('connection', 'refused', 'timed out', 'max retries')):
        return msg + hint
    if any(x in err_lower for x in ('certificate', 'ssl', 'tls')):
        return msg + ' Try disabling Verify SSL.' + hint
    resp = getattr(exc, 'response', None)
    if resp is not None:
        try:
            return f'HTTP {resp.status_code}: {msg}' + hint
        except Exception:
            pass
    return msg + hint


def _normalize_discovery_url(url: str) -> str:
    u = (url or '').strip()
    if not u:
        return ''
    if '://' not in u:
        u = 'https://' + u
    u = u.rstrip('/')
    if '/collections/' in u:
        u = u.split('/collections/')[0].rstrip('/')
    if u.endswith('/collections'):
        u = u[: -len('/collections')]
    if '/taxii2/' in u and not u.endswith('/taxii2'):
        idx = u.index('/taxii2')
        u = u[: idx + len('/taxii2')]
    elif not u.endswith('/taxii2'):
        u = u + '/taxii2'
    return u + '/'


def _make_session(
    username: str,
    password: str,
    api_key: str,
    verify_ssl: bool,
) -> requests.Session:
    sess = requests.Session()
    configure_requests_session(sess)
    sess.verify = verify_ssl
    key = (api_key or '').strip()
    user = (username or '').strip()
    pwd = (password or '').strip()
    if key:
        sess.headers['Authorization'] = f'Bearer {key}'
    elif user and pwd:
        sess.auth = HTTPBasicAuth(user, pwd)
    return sess


def _taxii_get_json(sess: requests.Session, url: str, *, accept: str = TAXII_ACCEPT) -> dict:
    headers = {'Accept': accept}
    r = sess.get(url, headers=headers, timeout=45)
    r.raise_for_status()
    return r.json()


def _resolve_api_root(sess: requests.Session, discovery_url: str, api_root_id: str) -> tuple[str, str | None]:
    """Return (api_root_url, error)."""
    disc = _taxii_get_json(sess, discovery_url)
    roots = disc.get('api_roots') or []
    if not roots:
        return '', 'Discovery returned no api_roots'
    want = (api_root_id or '').strip()
    if want:
        for root in roots:
            if want in root.rstrip('/').split('/'):
                return root if root.endswith('/') else root + '/', None
        return '', f'API root "{want}" not found in discovery'
    root = roots[0]
    return (root if root.endswith('/') else root + '/'), None


def _resolve_collection_id(sess: requests.Session, api_root: str, collection_id: str) -> tuple[str, str | None]:
    coll_url = urljoin(api_root, 'collections/')
    data = _taxii_get_json(sess, coll_url)
    colls = data.get('collections') or []
    if not colls:
        return '', 'No collections on TAXII server'
    want = (collection_id or '').strip()
    if want:
        for c in colls:
            cid = (c.get('id') or '').strip()
            if cid == want:
                return cid, None
        return '', f'Collection "{want}" not found'
    first = colls[0]
    return (first.get('id') or '').strip(), None


def _iter_indicators_from_payload(obj: Any):
    if obj is None:
        return
    if isinstance(obj, list):
        for item in obj:
            yield from _iter_indicators_from_payload(item)
        return
    if not isinstance(obj, dict):
        return
    otype = (obj.get('type') or '').lower()
    if otype == 'bundle':
        for sub in obj.get('objects') or []:
            yield from _iter_indicators_from_payload(sub)
        return
    if otype == 'indicator':
        yield obj


def _stix_ts_to_sort_key(modified: str) -> int:
    if not modified:
        return 0
    try:
        s = modified.replace('Z', '+00:00')
        dt = datetime.fromisoformat(s)
        return int(dt.timestamp())
    except Exception:
        return 0


def _added_after_iso(last_sync: str, last_days: int) -> str:
    floor = datetime.now(timezone.utc) - timedelta(days=max(last_days, 1))
    floor_naive = floor.replace(tzinfo=None)
    use = floor_naive
    last_dt = None
    s = (last_sync or '').strip()
    if s:
        try:
            if s.endswith('Z'):
                s = s[:-1] + '+00:00'
            last_dt = datetime.fromisoformat(s)
            if last_dt.tzinfo is not None:
                last_dt = last_dt.replace(tzinfo=None)
            if last_dt > use:
                use = last_dt
        except (ValueError, TypeError):
            pass
    aware = use.replace(tzinfo=timezone.utc)
    return aware.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def fetch_indicators(
    discovery_url: str,
    *,
    api_root_id: str = '',
    collection_id: str = '',
    username: str = '',
    password: str = '',
    api_key: str = '',
    verify_ssl: bool = False,
    last_days: int = 30,
    last_sync: str = '',
    skip_revoked: bool = True,
) -> tuple[list[dict], str | None]:
    """
    Pull STIX indicators from remote TAXII 2.1 collection.
    Returns list of {value, tg_type, stix_id, name, description} and optional error.
    """
    disc = _normalize_discovery_url(discovery_url)
    if not disc:
        return [], 'TAXII discovery URL is required'

    sess = _make_session(username, password, api_key, verify_ssl)
    try:
        api_root, err = _resolve_api_root(sess, disc, api_root_id)
        if err:
            return [], err
        coll_id, err = _resolve_collection_id(sess, api_root, collection_id)
        if err:
            return [], err

        added_after = _added_after_iso(last_sync, last_days)
        base_objs = urljoin(api_root, f'collections/{coll_id}/objects/')
        next_url: Optional[str] = base_objs
        params: Optional[dict] = {'added_after': added_after, 'limit': DEFAULT_PAGE_LIMIT}
        raw_indicators: list[tuple[int, dict]] = []
        pages = 0

        while next_url and pages < MAX_PAGES:
            pages += 1
            if params:
                r = sess.get(next_url, headers={'Accept': TAXII_ACCEPT}, params=params, timeout=120)
            else:
                r = sess.get(next_url, headers={'Accept': TAXII_ACCEPT}, timeout=120)
            r.raise_for_status()
            data = r.json()
            for ind in _iter_indicators_from_payload(data.get('objects')):
                if skip_revoked and ind.get('revoked') is True:
                    continue
                pattern = (ind.get('pattern') or '').strip()
                if not pattern:
                    continue
                parsed = parse_indicator_pattern(pattern)
                if not parsed:
                    continue
                tg_type, value = parsed
                stix_id = (ind.get('id') or '')[:128]
                name = (ind.get('name') or '')[:200]
                desc = (ind.get('description') or '')[:500]
                mod = ind.get('modified') or ind.get('created') or ''
                raw_indicators.append((_stix_ts_to_sort_key(mod), {
                    'value': value,
                    'tg_type': tg_type,
                    'stix_id': stix_id,
                    'name': name,
                    'description': desc,
                }))
            next_url = (data.get('next') or '').strip() or None
            params = None

        raw_indicators.sort(key=lambda x: x[0], reverse=True)
        seen: set[tuple[str, str]] = set()
        results = []
        for _ts, item in raw_indicators:
            key = (item['tg_type'], item['value'].lower())
            if key in seen:
                continue
            seen.add(key)
            results.append(item)
        return results, None
    except requests.RequestException as e:
        _log.warning('TAXII fetch failed: %s', e)
        return [], 'TAXII request failed: ' + _connection_error_message(e, disc)
    except Exception as e:
        _log.exception('TAXII fetch unexpected error')
        return [], str(e)[:300]


def test_connection_steps(
    discovery_url: str,
    *,
    api_root_id: str = '',
    collection_id: str = '',
    username: str = '',
    password: str = '',
    api_key: str = '',
    verify_ssl: bool = False,
) -> list[dict]:
    steps: list[dict] = []
    disc = _normalize_discovery_url(discovery_url)
    if not disc:
        steps.append({'step': 'Check URL', 'status': 'fail', 'message': 'TAXII discovery URL is required'})
        return steps
    steps.append({'step': 'Check URL', 'status': 'ok', 'message': disc[:80]})

    if not (api_key or '').strip() and not ((username or '').strip() and (password or '').strip()):
        steps.append({
            'step': 'Check credentials',
            'status': 'fail',
            'message': 'Set API key (Bearer) or username + password (Basic)',
        })
        return steps
    steps.append({'step': 'Check credentials', 'status': 'ok', 'message': 'Credentials configured'})

    sess = _make_session(username, password, api_key, verify_ssl)
    try:
        disc_data = _taxii_get_json(sess, disc)
        title = (disc_data.get('title') or 'TAXII server')[:80]
        steps.append({'step': 'Discovery', 'status': 'ok', 'message': title})
        api_root, err = _resolve_api_root(sess, disc, api_root_id)
        if err:
            steps.append({'step': 'API Root', 'status': 'fail', 'message': err})
            return steps
        steps.append({'step': 'API Root', 'status': 'ok', 'message': api_root[:80]})
        coll_id, err = _resolve_collection_id(sess, api_root, collection_id)
        if err:
            steps.append({'step': 'Collection', 'status': 'fail', 'message': err})
            return steps
        steps.append({'step': 'Collection', 'status': 'ok', 'message': f'id={coll_id}'})
    except requests.RequestException as e:
        steps.append({'step': 'Connect', 'status': 'fail', 'message': _connection_error_message(e, disc)})
    except Exception as e:
        steps.append({'step': 'Connect', 'status': 'fail', 'message': str(e)[:200]})
    return steps


def sync_to_db(
    indicators: list[dict],
    taxii_user_id: int,
    taxii_username: str,
    default_ttl_days: int | None = None,
    geoip_reader=None,
    *,
    ioc_import_mode: str = 'pending',
    get_setting_fn=None,
) -> dict:
    from extensions import db
    from models import IOC, IocHistory
    from sqlalchemy import func
    from utils.ioc_import_mode import normalize_ioc_import_mode

    mode = normalize_ioc_import_mode(ioc_import_mode, 'pending')

    added = 0
    skipped = 0
    errors = 0
    invalid = 0
    blocked = 0
    pending_added = 0
    added_samples: list[dict] = []
    pending_samples: list[dict] = []
    invalid_samples: list[dict] = []
    publish_keys: list[tuple[str, str]] = []

    exp_date = None
    if default_ttl_days and default_ttl_days > 0:
        exp_date = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=default_ttl_days)

    for ind in indicators:
        value = ind['value']
        tg_type = ind['tg_type']
        stix_id = ind.get('stix_id', '')
        name = ind.get('name', '')
        desc = ind.get('description', '')

        if not validate_ioc(value, tg_type):
            invalid += 1
            if len(invalid_samples) < 30:
                invalid_samples.append({'type': tg_type, 'value': value[:120]})
            continue

        existing = IOC.query.filter(
            IOC.type == tg_type,
            func.lower(IOC.value) == value.lower(),
        ).first()
        if existing:
            skipped += 1
            continue

        if mode == 'block':
            blocked += 1
            continue

        pending_approval = mode == 'pending'

        comment_parts = []
        if name:
            comment_parts.append(f'[TAXII] {name}')
        if desc:
            comment_parts.append(desc)
        comment = ' | '.join(comment_parts) if comment_parts else '[TAXII Import]'

        agg = compute_ioc_aggregate_fields(tg_type, value, geoip_reader)
        try:
            ioc = IOC(
                type=tg_type,
                value=value,
                analyst=taxii_username,
                ticket_id=f'TAXII-{stix_id[-32:]}' if stix_id else None,
                comment=comment[:1000],
                expiration_date=exp_date,
                user_id=taxii_user_id,
                submission_method='import',
                pending_approval=pending_approval,
                country_code=agg.get('country_code'),
                tld=agg.get('tld'),
                email_domain=agg.get('email_domain'),
            )
            db.session.add(ioc)
            db.session.add(IocHistory(
                ioc_type=tg_type,
                ioc_value=value,
                event_type='created',
                username=taxii_username,
                payload=json.dumps({
                    'source': 'taxii',
                    'stix_id': stix_id,
                    'pending_approval': pending_approval,
                }),
            ))
            added += 1
            if pending_approval:
                pending_added += 1
                if len(pending_samples) < 100:
                    pending_samples.append({'type': tg_type, 'value': value})
            else:
                publish_keys.append((tg_type, value))
                if len(added_samples) < 100:
                    added_samples.append({'type': tg_type, 'value': value})
        except Exception as e:
            _log.warning('TAXII sync insert error for %s: %s', value[:80], e)
            errors += 1

    if added > 0:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            _log.exception('TAXII sync commit failed: %s', e)
            return {
                'added': 0, 'skipped': skipped, 'errors': added + errors, 'error': str(e),
                'blocked': blocked, 'pending_added': 0,
                'added_samples': [], 'pending_samples': [], 'invalid_samples': invalid_samples,
            }

        if mode == 'auto' and publish_keys and get_setting_fn:
            try:
                from utils.ioc_publish import publish_ioc_row
                for tg_type, value in publish_keys:
                    pub_row = IOC.query.filter(
                        IOC.type == tg_type,
                        func.lower(IOC.value) == value.lower(),
                    ).first()
                    if pub_row and not pub_row.pending_approval:
                        publish_ioc_row(pub_row, get_setting=get_setting_fn)
            except Exception as e:
                _log.warning('TAXII IOC publish after sync failed: %s', e)

    return {
        'added': added,
        'skipped': skipped,
        'errors': errors,
        'invalid': invalid,
        'blocked': blocked,
        'pending_added': pending_added,
        'added_samples': added_samples,
        'pending_samples': pending_samples,
        'invalid_samples': invalid_samples,
        'ioc_import_mode': mode,
    }


def ensure_taxii_user(username: str = 'taxii_sync') -> tuple[int, str]:
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
    db.session.add(UserProfile(user_id=user.id, display_name='TAXII Sync'))
    db.session.commit()
    _log.info('Created TAXII sync user: %s (id=%d)', username, user.id)
    return user.id, user.username


_LOCK_KEY = 'taxii_sync_lock'
_LOCK_TIMEOUT_SECONDS = 600


def _acquire_lock() -> bool:
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
    from extensions import db
    from models import SystemSetting
    row = SystemSetting.query.filter_by(key=_LOCK_KEY).first()
    if row:
        row.value = ''
        db.session.commit()


def run_sync(settings: dict, log_lines: list | None = None) -> dict:
    def log(step: str, status: str, message: str = '') -> None:
        if log_lines is not None:
            log_lines.append({'step': step, 'status': status, 'message': message})

    from taxii_pull_settings import normalize_sync_settings
    settings = normalize_sync_settings(settings)

    if not _acquire_lock():
        log('Acquire lock', 'fail', 'Another TAXII sync is already running.')
        return {'success': False, 'error': 'Another TAXII sync is already running.'}
    log('Acquire lock', 'ok', 'Sync lock acquired')
    try:
        url = (settings.get('taxii_discovery_url') or '').strip()
        if not url:
            log('Check config', 'fail', 'TAXII discovery URL not configured')
            return {'success': False, 'error': 'TAXII discovery URL not configured'}
        api_key = (settings.get('taxii_api_key') or '').strip()
        user = (settings.get('taxii_username') or '').strip()
        pwd = (settings.get('taxii_password') or '').strip()
        if not api_key and not (user and pwd):
            log('Check config', 'fail', 'TAXII credentials required (API key or username/password)')
            return {'success': False, 'error': 'TAXII credentials required'}
        log('Check config', 'ok', 'URL and credentials set')

        verify_ssl = (settings.get('taxii_verify_ssl') or 'false').lower() == 'true'
        try:
            last_days = int(settings.get('taxii_last_days') or 30)
        except (ValueError, TypeError):
            last_days = 30
        skip_revoked = (settings.get('taxii_skip_revoked') or 'true').lower() != 'false'

        default_ttl = None
        ttl_raw = (settings.get('taxii_default_ttl') or '').strip().lower()
        if ttl_raw and ttl_raw not in ('permanent', '0'):
            try:
                default_ttl = int(ttl_raw)
            except (ValueError, TypeError):
                pass

        sync_user = (settings.get('taxii_sync_user') or 'taxii_sync').strip()
        user_id, username = ensure_taxii_user(sync_user)
        log('Ensure TAXII user', 'ok', f'User: {username} (id={user_id})')

        last_sync = (settings.get('taxii_last_sync') or '').strip()

        log('Fetch indicators from TAXII', 'ok', 'Requesting objects...')
        indicators, err = fetch_indicators(
            url,
            api_root_id=settings.get('taxii_api_root_id') or '',
            collection_id=settings.get('taxii_collection_id') or '',
            username=user,
            password=pwd,
            api_key=api_key,
            verify_ssl=verify_ssl,
            last_days=last_days,
            last_sync=last_sync,
            skip_revoked=skip_revoked,
        )
        if err:
            log('Fetch indicators from TAXII', 'fail', err)
            return {'success': False, 'error': err, 'fetched': 0}
        log('Fetch indicators from TAXII', 'ok', f'Fetched {len(indicators)} indicators')

        ioc_mode = settings.get('taxii_ioc_import_mode') or 'pending'
        log('Import policy', 'ok', f'IOC={ioc_mode}')

        geoip_reader = None
        try:
            from app import geoip_reader as _gr
            geoip_reader = _gr
        except ImportError:
            pass
        get_setting_fn = None
        try:
            from app import _get_setting
            get_setting_fn = _get_setting
        except ImportError:
            pass
        result = sync_to_db(
            indicators, user_id, username, default_ttl, geoip_reader=geoip_reader,
            ioc_import_mode=ioc_mode, get_setting_fn=get_setting_fn,
        )
        result['success'] = True
        result['fetched'] = len(indicators)
        log(
            'Insert into ZIoCHub', 'ok',
            f"mode={ioc_mode} added={result.get('added', 0)} "
            f"pending={result.get('pending_added', 0)} blocked={result.get('blocked', 0)} "
            f"skipped={result.get('skipped', 0)} errors={result.get('errors', 0)}",
        )
        return result
    finally:
        _release_lock()
