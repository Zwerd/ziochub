"""
AdversaryGraph inbound pull — IOC Library + Detection Studio YARA rules.

Requires: requests (see requirements.txt). AdversaryGraph API (FastAPI) must be reachable.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urljoin

import requests

from utils.http_identity import configure_requests_session
from utils.validation import validate_ioc
from utils.ioc_aggregate_fields import compute_ioc_aggregate_fields
from utils.yara_utils import (
    sanitize_yara_filename,
    validate_yara_syntax,
    yara_content_sha256,
)
from utils.champs import compute_yara_quality_points

_log = logging.getLogger('ziochub.adversarygraph')

AG_TYPE_MAP = {
    # Normalized AdversaryGraph types (v3.x folds sha256_hash → sha256, etc.)
    'ipv4': 'IP',
    'ipv6': 'IP',
    'ip': 'IP',
    'ip:port': 'IP',
    'ipv4:port': 'IP',
    'domain': 'Domain',
    'hostname': 'Domain',
    'url': 'URL',
    'uri': 'URL',
    'link': 'URL',
    'email': 'Email',
    'email-src': 'Email',
    'email-dst': 'Email',
    'md5': 'Hash',
    'sha1': 'Hash',
    'sha256': 'Hash',
    'sha512': 'Hash',
    'md5_hash': 'Hash',
    'sha1_hash': 'Hash',
    'sha256_hash': 'Hash',
    'filehash-sha256': 'Hash',
    'file_hash_sha256': 'Hash',
    'sha-256': 'Hash',
    'ssdeep': 'Hash',
}

# AdversaryGraph GET /api/ioc/library sort values (last_seen_desc, etc.)
AG_LIBRARY_SORT = 'last_seen_desc'

LIBRARY_PAGE_LIMIT = 500
DETECTIONS_LIMIT = 200

_LOCK_KEY = 'adversarygraph_sync_lock'
_LOCK_TIMEOUT_SECONDS = 600


def _connection_error_message(exc: Exception, url: str) -> str:
    msg = str(exc).strip()[:300]
    hint = (
        ' Check: (1) AdversaryGraph API URL includes scheme and port, e.g. http://127.0.0.1:8000 ; '
        '(2) docker compose stack is running ; '
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


def _normalize_base_url(url: str) -> str:
    u = (url or '').strip().rstrip('/')
    if not u:
        return ''
    if '://' not in u:
        u = 'http://' + u
    return u


def _auth_headers(settings: dict) -> dict[str, str]:
    headers: dict[str, str] = {'Accept': 'application/json'}
    user = (settings.get('adversarygraph_auth_user') or '').strip()
    roles = (settings.get('adversarygraph_auth_roles') or 'analyst').strip() or 'analyst'
    if user:
        headers['X-Auth-User'] = user
        headers['X-Auth-Roles'] = roles
    return headers


def _make_session(settings: dict) -> requests.Session:
    sess = requests.Session()
    configure_requests_session(sess)
    verify = (settings.get('adversarygraph_verify_ssl') or 'false').lower() == 'true'
    sess.verify = verify
    sess.headers.update(_auth_headers(settings))
    return sess


def _api_get(session: requests.Session, base_url: str, path: str, *, timeout: int = 60, params: dict | None = None) -> Any:
    url = urljoin(base_url + '/', path.lstrip('/'))
    resp = session.get(url, params=params or {}, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def map_ag_type(ag_type: str) -> str | None:
    t = (ag_type or '').strip().lower()
    if not t:
        return None
    if t in AG_TYPE_MAP:
        return AG_TYPE_MAP[t]
    # Legacy/provider labels not yet in map: try suffix normalization
    for suffix, ztype in (('_hash', 'Hash'), ('-hash', 'Hash')):
        if t.endswith(suffix):
            base = t[: -len(suffix)]
            if base in ('md5', 'sha1', 'sha256', 'sha512'):
                return ztype
    return None


def _parse_csv_filter(raw: str) -> list[str]:
    return [x.strip().lower() for x in (raw or '').split(',') if x.strip()]


def _parse_actor_filter(raw: str) -> list[str]:
    """ATT&CK group IDs (G0006) — preserve case for API query."""
    return [x.strip().upper() for x in (raw or '').split(',') if x.strip()]


def _library_item_to_row(item: dict) -> dict | None:
    """Map AdversaryGraph IOCLibraryItemOut → internal sync row."""
    if not isinstance(item, dict):
        return None
    ag_type = (item.get('type') or '').strip().lower()
    tg_type = map_ag_type(ag_type)
    if not tg_type:
        return None
    value = _clean_value(item.get('value') or '', tg_type)
    if not value:
        return None

    actors = item.get('actors') or []
    actor_ids: list[str] = []
    actor_names: list[str] = []
    if isinstance(actors, list):
        for ref in actors:
            if not isinstance(ref, dict):
                continue
            aid = (ref.get('actor_attack_id') or '').strip().upper()
            aname = (ref.get('actor_name') or '').strip()
            if aid:
                actor_ids.append(aid)
            if aname:
                actor_names.append(aname)

    campaign = (item.get('campaign') or '').strip()
    if not campaign and actor_names:
        campaign = actor_names[0]

    technique_ids = list(item.get('technique_ids') or [])
    tags_raw = item.get('tags') or []
    tags: list[str] = []
    if isinstance(tags_raw, list):
        tags = [str(t).strip() for t in tags_raw if t]
    elif isinstance(tags_raw, str) and tags_raw.strip():
        tags = [tags_raw.strip()]

    for aid in actor_ids:
        tags.append(aid)
    for tid in technique_ids:
        ts = str(tid).strip().upper()
        if ts:
            tags.append(ts)

    tlp = (item.get('tlp') or '').strip().upper()
    confidence = item.get('confidence')
    try:
        confidence = int(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None

    return {
        'ag_id': item.get('id'),
        'value': value,
        'tg_type': tg_type,
        'source': item.get('source') or '',
        'source_url': item.get('source_url') or '',
        'comment': item.get('description') or '',
        'tags': tags,
        'technique_ids': technique_ids,
        'malware_family': item.get('malware_family') or '',
        'campaign': campaign,
        'actor_ids': actor_ids,
        'actor_names': actor_names,
        'confidence': confidence,
        'tlp': tlp,
        'last_seen': item.get('last_seen') or item.get('first_seen'),
    }


def _clean_value(value: str, tg_type: str) -> str:
    val = (value or '').strip()
    if tg_type == 'IP' and '|' in val:
        val = val.split('|')[0].strip()
    return val


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace('Z', '+00:00'))
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except (ValueError, TypeError):
        return None


def _within_lookback(ts: str | None, cutoff: datetime) -> bool:
    dt = _parse_ts(ts)
    if dt is None:
        return True
    return dt >= cutoff


def test_connection_steps(url: str, verify_ssl: bool = False, auth_user: str = '', auth_roles: str = 'analyst') -> list[dict]:
    steps: list[dict] = []
    base = _normalize_base_url(url)
    if not base:
        steps.append({'step': 'Check URL', 'status': 'fail', 'message': 'AdversaryGraph API URL is required'})
        return steps
    steps.append({'step': 'Check URL', 'status': 'ok', 'message': base[:80]})

    settings = {
        'adversarygraph_url': base,
        'adversarygraph_verify_ssl': 'true' if verify_ssl else 'false',
        'adversarygraph_auth_user': auth_user,
        'adversarygraph_auth_roles': auth_roles or 'analyst',
    }
    try:
        sess = _make_session(settings)
        health = _api_get(sess, base, '/api/health', timeout=15)
        status = health.get('status') if isinstance(health, dict) else 'ok'
        version = ''
        if isinstance(health, dict):
            version = str(health.get('version') or health.get('app_version') or '').strip()
        msg = f'Health: {status}'
        if version:
            msg += f' (AdversaryGraph {version})'
        steps.append({'step': 'GET /api/health', 'status': 'ok', 'message': msg})
    except Exception as e:
        steps.append({'step': 'GET /api/health', 'status': 'fail', 'message': _connection_error_message(e, base)})
        return steps

    try:
        lib = _api_get(sess, base, '/api/ioc/library', timeout=30, params={'limit': 1, 'offset': 0})
        total = lib.get('total', 0) if isinstance(lib, dict) else 0
        steps.append({'step': 'GET /api/ioc/library', 'status': 'ok', 'message': f'IOC Library reachable ({total} total)'})
    except Exception as e:
        steps.append({'step': 'GET /api/ioc/library', 'status': 'fail', 'message': _connection_error_message(e, base)})

    try:
        det = _api_get(sess, base, '/api/pipeline/detections/versions', timeout=30)
        count = len(det) if isinstance(det, list) else 0
        yara_n = sum(1 for row in (det or []) if isinstance(row, dict) and (row.get('format') or '').lower() == 'yara')
        steps.append({
            'step': 'GET /api/pipeline/detections/versions',
            'status': 'ok',
            'message': f'Detection Studio reachable ({yara_n} YARA of {count} versions)',
        })
    except Exception as e:
        steps.append({
            'step': 'GET /api/pipeline/detections/versions',
            'status': 'fail',
            'message': _connection_error_message(e, base),
        })

    return steps


def fetch_ioc_library(settings: dict) -> tuple[list[dict], str | None]:
    base = _normalize_base_url(settings.get('adversarygraph_url') or '')
    if not base:
        return [], 'AdversaryGraph API URL is not configured'

    try:
        last_days = int(settings.get('adversarygraph_last_days') or 30)
    except (ValueError, TypeError):
        last_days = 30
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, last_days))

    filter_types = _parse_csv_filter(settings.get('adversarygraph_filter_types') or '')
    filter_sources = set(_parse_csv_filter(settings.get('adversarygraph_filter_sources') or ''))
    filter_actors = _parse_actor_filter(settings.get('adversarygraph_filter_actors') or '')
    try:
        min_confidence = int(settings.get('adversarygraph_min_confidence') or 0)
    except (ValueError, TypeError):
        min_confidence = 0
    min_confidence = max(0, min(100, min_confidence))

    sess = _make_session(settings)

    def _fetch_pages(api_params: dict[str, Any]) -> tuple[list[dict], str | None]:
        results: list[dict] = []
        offset = 0
        total = None
        while True:
            params: dict[str, Any] = {
                'limit': LIBRARY_PAGE_LIMIT,
                'offset': offset,
                'sort': AG_LIBRARY_SORT,
                **api_params,
            }
            try:
                data = _api_get(sess, base, '/api/ioc/library', timeout=120, params=params)
            except Exception as e:
                return results, _connection_error_message(e, base)
            if not isinstance(data, dict):
                return results, 'Unexpected IOC library response'
            if total is None:
                total = int(data.get('total') or 0)
            items = data.get('items') or []
            if not items:
                break
            for item in items:
                row = _library_item_to_row(item)
                if not row:
                    continue
                ag_type = (item.get('type') or '').strip().lower()
                if filter_types and ag_type not in filter_types:
                    continue
                source = (row.get('source') or '').strip().lower()
                if filter_sources and source not in filter_sources:
                    continue
                if filter_actors:
                    row_actors = {a.upper() for a in (row.get('actor_ids') or [])}
                    if not row_actors.intersection(filter_actors):
                        continue
                conf = row.get('confidence')
                if min_confidence > 0 and conf is not None and conf < min_confidence:
                    continue
                last_seen = row.get('last_seen')
                if not _within_lookback(last_seen, cutoff):
                    continue
                results.append(row)
            offset += len(items)
            if offset >= total or len(items) < LIBRARY_PAGE_LIMIT:
                break
        return results, None

    # Server-side filters: type (single), source (single), actor (multi) per AdversaryGraph API
    base_params: dict[str, Any] = {}
    if len(filter_types) == 1:
        base_params['type'] = filter_types[0]
    if len(filter_sources) == 1:
        base_params['source'] = next(iter(filter_sources))
    if filter_actors:
        base_params['actor'] = filter_actors

    if len(filter_types) > 1:
        merged: list[dict] = []
        seen_keys: set[tuple[str, str]] = set()
        for ag_type in filter_types:
            type_params = {**base_params, 'type': ag_type}
            chunk, err = _fetch_pages(type_params)
            if err and not chunk:
                return [], err
            for row in chunk:
                key = (row['tg_type'], row['value'].lower())
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                merged.append(row)
        results = merged
    else:
        results, err = _fetch_pages(base_params)
        if err:
            return results, err

    # Dedupe by (type, value) — library sort is last_seen_desc so first wins
    seen: set[tuple[str, str]] = set()
    deduped: list[dict] = []
    for row in results:
        key = (row['tg_type'], row['value'].lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped, None


def fetch_yara_detections(settings: dict) -> tuple[list[dict], str | None]:
    base = _normalize_base_url(settings.get('adversarygraph_url') or '')
    if not base:
        return [], 'AdversaryGraph API URL is not configured'

    pull_yara = (settings.get('adversarygraph_pull_yara') or 'true').lower() != 'false'
    if not pull_yara:
        return [], None

    try:
        last_days = int(settings.get('adversarygraph_last_days') or 30)
    except (ValueError, TypeError):
        last_days = 30
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, last_days))

    sess = _make_session(settings)
    try:
        rows = _api_get(sess, base, '/api/pipeline/detections/versions', timeout=120)
    except Exception as e:
        return [], _connection_error_message(e, base)

    if not isinstance(rows, list):
        return [], 'Unexpected detections response'

    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if (row.get('format') or '').strip().lower() != 'yara':
            continue
        content = (row.get('content') or '').strip()
        if not content:
            continue
        created = row.get('created_at') or row.get('updated_at')
        if not _within_lookback(str(created) if created else None, cutoff):
            continue
        det_id = str(row.get('id') or row.get('detection_id') or '').strip()
        out.append({
            'id': det_id,
            'title': (row.get('title') or 'rule').strip(),
            'technique_id': (row.get('technique_id') or '').strip(),
            'content': content,
            'created_at': created,
            'format': (row.get('format') or 'yara').strip().lower(),
        })
    return out, None


def ensure_sync_user(username: str = 'adversarygraph_sync') -> tuple[int, str]:
    """Ensure a local system user for AdversaryGraph sync exists."""
    from extensions import db
    from models import User, UserProfile

    uname = (username or 'adversarygraph_sync').strip() or 'adversarygraph_sync'
    user = User.query.filter_by(username=uname).first()
    if user:
        if user.source != 'system':
            user.source = 'system'
            db.session.commit()
        return user.id, user.username

    user = User(
        username=uname,
        password_hash=None,
        source='system',
        is_admin=False,
        is_active=True,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(UserProfile(user_id=user.id, display_name='AdversaryGraph Sync'))
    db.session.commit()
    _log.info('Created AdversaryGraph sync user: %s (id=%d)', uname, user.id)
    return user.id, user.username


def _build_ioc_comment(row: dict) -> str:
    parts = ['[AdversaryGraph]']
    if row.get('source'):
        parts.append(str(row['source']))
    if row.get('malware_family'):
        parts.append(f"family={row['malware_family']}")
    if row.get('campaign'):
        parts.append(f"campaign={row['campaign']}")
    actor_ids = row.get('actor_ids') or []
    if actor_ids:
        parts.append(f"actors={','.join(actor_ids[:5])}")
    if row.get('tlp'):
        parts.append(f"TLP:{row['tlp']}")
    conf = row.get('confidence')
    if conf is not None:
        parts.append(f"confidence={conf}")
    if row.get('comment'):
        parts.append(str(row['comment'])[:400])
    return ' | '.join(parts)[:1000]


def _build_ioc_tags(row: dict) -> str:
    tags = []
    for t in (row.get('tags') or []):
        if t:
            tags.append(str(t).strip().lower())
    for tid in (row.get('technique_ids') or []):
        tid_s = str(tid).strip().upper()
        if tid_s:
            tags.append(tid_s)
    for aid in (row.get('actor_ids') or []):
        aid_s = str(aid).strip().upper()
        if aid_s:
            tags.append(aid_s)
    if row.get('source'):
        tags.append(f"ag-source:{str(row['source']).strip().lower()}")
    if row.get('tlp'):
        tags.append(f"tlp:{str(row['tlp']).strip().lower()}")
    ag_id = row.get('ag_id')
    if ag_id is not None:
        tags.append(f"ag-id:{ag_id}")
    return json.dumps(list(dict.fromkeys(tags))[:30])


def sync_iocs_to_db(
    indicators: list[dict],
    user_id: int,
    username: str,
    default_ttl_days: int | None = None,
    geoip_reader=None,
    *,
    ioc_import_mode: str = 'auto',
    get_setting_fn=None,
) -> dict:
    from extensions import db
    from models import IOC, IocHistory
    from sqlalchemy import func
    from adversarygraph_settings import normalize_import_mode

    mode = normalize_import_mode(ioc_import_mode, 'pending')

    added = skipped = errors = invalid = blocked = pending_added = 0
    added_samples: list[dict] = []
    pending_samples: list[dict] = []
    invalid_samples: list[dict] = []
    publish_keys: list[tuple[str, str]] = []

    exp_date = None
    if default_ttl_days and default_ttl_days > 0:
        exp_date = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=default_ttl_days)

    for row in indicators:
        value = row['value']
        tg_type = row['tg_type']
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
        agg = compute_ioc_aggregate_fields(tg_type, value, geoip_reader)
        ticket = f"AG-{(row.get('source') or 'ioc')[:20]}".replace(' ', '-')
        try:
            db.session.add(IOC(
                type=tg_type,
                value=value,
                analyst=username,
                ticket_id=ticket[:255] or None,
                comment=_build_ioc_comment(row),
                tags=_build_ioc_tags(row),
                expiration_date=exp_date,
                user_id=user_id,
                submission_method='import',
                pending_approval=pending_approval,
                country_code=agg.get('country_code'),
                tld=agg.get('tld'),
                email_domain=agg.get('email_domain'),
            ))
            db.session.add(IocHistory(
                ioc_type=tg_type,
                ioc_value=value,
                event_type='created',
                username=username,
                payload=json.dumps({
                    'source': 'adversarygraph',
                    'ag_source': row.get('source'),
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
            _log.warning('AdversaryGraph IOC insert error for %s: %s', value[:80], e)
            errors += 1

    if added > 0:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {
                'added': 0, 'skipped': skipped, 'errors': added + errors, 'invalid': invalid,
                'blocked': blocked, 'pending_added': 0,
                'error': str(e), 'added_samples': [], 'pending_samples': [], 'invalid_samples': invalid_samples,
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
                _log.warning('AdversaryGraph IOC publish after sync failed: %s', e)

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


def _yara_filename_from_detection(title: str, det_id: str) -> str | None:
    base = re.sub(r'[^a-zA-Z0-9._-]', '_', (title or 'rule').strip())[:100]
    if not base.lower().endswith('.yar'):
        base = f'{base}.yar'
    safe, _ = sanitize_yara_filename(base)
    if safe:
        return safe
    short = re.sub(r'[^a-f0-9-]', '', (det_id or ''))[:12] or 'rule'
    safe, _ = sanitize_yara_filename(f'ag_{short}.yar')
    return safe


def _yara_import_mode(yara_import_mode: str) -> str:
    from adversarygraph_settings import normalize_import_mode
    return normalize_import_mode(yara_import_mode, 'pending')


def sync_yara_to_db(
    detections: list[dict],
    user_id: int,
    username: str,
    *,
    data_yara: str,
    data_pending: str,
    data_rejected: str,
    yara_import_mode: str = 'auto',
    get_setting_fn=None,
) -> dict:
    from extensions import db
    from models import YaraRule
    from sqlalchemy import or_

    mode = _yara_import_mode(yara_import_mode)
    added = skipped = errors = invalid = blocked = pending_added = 0
    added_samples: list[dict] = []
    pending_samples: list[dict] = []

    for det in detections:
        if mode == 'block':
            blocked += 1
            continue

        content = det.get('content') or ''
        ok, err = validate_yara_syntax(content)
        if not ok:
            invalid += 1
            continue

        content_hash = yara_content_sha256(content)
        dup = YaraRule.query.filter(
            or_(
                YaraRule.content_sha256 == content_hash,
            )
        ).first()
        if dup:
            skipped += 1
            continue

        safe_filename = _yara_filename_from_detection(det.get('title') or '', det.get('id') or '')
        if not safe_filename:
            invalid += 1
            continue

        filepath_approved = os.path.join(data_yara, safe_filename)
        filepath_pending = os.path.join(data_pending, safe_filename)
        filepath_rejected = os.path.join(data_rejected, safe_filename)
        if (
            os.path.exists(filepath_approved)
            or os.path.exists(filepath_pending)
            or os.path.exists(filepath_rejected)
            or YaraRule.query.filter_by(filename=safe_filename).first()
        ):
            # Try unique name with AG id suffix
            alt = _yara_filename_from_detection('', det.get('id') or safe_filename)
            if not alt or alt == safe_filename or YaraRule.query.filter_by(filename=alt).first():
                skipped += 1
                continue
            safe_filename = alt
            filepath_approved = os.path.join(data_yara, safe_filename)
            filepath_pending = os.path.join(data_pending, safe_filename)

        rule_status = 'pending' if mode == 'pending' else 'approved'
        save_path = filepath_pending if mode == 'pending' else filepath_approved
        ticket_id = f"AG-{(det.get('id') or '')[:36]}".strip('-') or None
        technique = (det.get('technique_id') or '').strip()
        comment_parts = ['[AdversaryGraph] Imported YARA rule']
        if technique:
            comment_parts.append(f'TTP: {technique}')
        comment = ' | '.join(comment_parts)

        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(content)
            db.session.add(YaraRule(
                filename=safe_filename,
                original_filename=safe_filename,
                analyst=username,
                ticket_id=ticket_id,
                comment=comment[:1000],
                quality_points=compute_yara_quality_points(content),
                status=rule_status,
                content_sha256=content_hash,
            ))
            db.session.commit()
            added += 1
            if rule_status == 'pending':
                pending_added += 1
                if len(pending_samples) < 50:
                    pending_samples.append({'filename': safe_filename, 'status': 'pending'})
            else:
                if len(added_samples) < 50:
                    added_samples.append({'filename': safe_filename, 'status': rule_status})
            if rule_status == 'approved':
                try:
                    from app import _log_champs_event
                    _log_champs_event('yara_upload', user_id=user_id, payload={'filename': safe_filename})
                except Exception:
                    pass
        except Exception as e:
            db.session.rollback()
            if os.path.exists(save_path):
                try:
                    os.remove(save_path)
                except OSError:
                    pass
            _log.warning('AdversaryGraph YARA insert failed for %s: %s', safe_filename, e)
            errors += 1

    return {
        'yara_added': added,
        'yara_skipped': skipped,
        'yara_errors': errors,
        'yara_invalid': invalid,
        'yara_blocked': blocked,
        'yara_pending_added': pending_added,
        'yara_pending': mode == 'pending',
        'yara_import_mode': mode,
        'yara_added_samples': added_samples,
        'yara_pending_samples': pending_samples,
    }


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


def run_sync(settings: dict, log_lines: list | None = None, get_setting_fn=None) -> dict:
    def log(step: str, status: str, message: str = '') -> None:
        if log_lines is not None:
            log_lines.append({'step': step, 'status': status, 'message': message})

    from adversarygraph_settings import normalize_sync_settings

    settings = normalize_sync_settings(settings)

    if not _acquire_lock():
        log('Acquire lock', 'fail', 'Another sync is already running. Try again later.')
        return {'success': False, 'error': 'Another sync is already running. Try again later.'}
    log('Acquire lock', 'ok', 'Sync lock acquired')

    try:
        url = (settings.get('adversarygraph_url') or '').strip()
        if not url:
            log('Check config', 'fail', 'AdversaryGraph API URL not configured')
            return {'success': False, 'error': 'AdversaryGraph API URL not configured'}
        log('Check config', 'ok', f'URL: {_normalize_base_url(url)[:80]}')

        default_ttl = None
        ttl_raw = (settings.get('adversarygraph_default_ttl') or '').strip().lower()
        if ttl_raw and ttl_raw not in ('permanent', '0'):
            try:
                default_ttl = int(ttl_raw)
            except (ValueError, TypeError):
                pass

        sync_user = (settings.get('adversarygraph_sync_user') or 'adversarygraph_sync').strip().lower()
        user_id, username = ensure_sync_user(sync_user)
        log('Ensure sync user', 'ok', f'User: {username} (id={user_id})')

        log('Fetch IOC library', 'ok', 'Requesting /api/ioc/library …')
        indicators, err = fetch_ioc_library(settings)
        if err:
            log('Fetch IOC library', 'fail', err)
            return {'success': False, 'error': err, 'fetched': 0}

        log('Fetch IOC library', 'ok', f'Fetched {len(indicators)} indicators (after filters)')
        geoip_reader = None
        try:
            from app import geoip_reader as _gr
            geoip_reader = _gr
        except ImportError:
            pass

        ioc_mode = settings.get('adversarygraph_ioc_import_mode') or 'pending'
        yara_mode = settings.get('adversarygraph_yara_import_mode') or 'pending'
        log('Import policy', 'ok', f'IOC={ioc_mode}, YARA={yara_mode}')

        if get_setting_fn is None:
            try:
                from app import _get_setting
                get_setting_fn = _get_setting
            except ImportError:
                get_setting_fn = lambda _k, d='': d

        ioc_result = sync_iocs_to_db(
            indicators, user_id, username, default_ttl, geoip_reader=geoip_reader,
            ioc_import_mode=ioc_mode, get_setting_fn=get_setting_fn,
        )
        log(
            'Insert IOCs',
            'ok',
            f"mode={ioc_mode} added={ioc_result.get('added', 0)} "
            f"pending={ioc_result.get('pending_added', 0)} blocked={ioc_result.get('blocked', 0)} "
            f"skipped={ioc_result.get('skipped', 0)} invalid={ioc_result.get('invalid', 0)} "
            f"errors={ioc_result.get('errors', 0)}",
        )

        yara_result: dict = {}
        pull_yara = (settings.get('adversarygraph_pull_yara') or 'true').lower() != 'false'
        if pull_yara:
            log('Fetch YARA rules', 'ok', 'Requesting Detection Studio versions …')
            detections, yerr = fetch_yara_detections(settings)
            if yerr:
                log('Fetch YARA rules', 'fail', yerr)
                yara_result = {'yara_error': yerr}
            else:
                log('Fetch YARA rules', 'ok', f'Fetched {len(detections)} YARA detection(s)')
                try:
                    from flask import current_app
                    data_yara = current_app.config.get('DATA_YARA') or ''
                    data_pending = current_app.config.get('DATA_YARA_PENDING') or ''
                    data_rejected = current_app.config.get('DATA_YARA_REJECTED') or ''
                except Exception:
                    import app as app_module
                    data_yara = app_module.DATA_YARA
                    data_pending = app_module.DATA_YARA_PENDING
                    data_rejected = app_module.DATA_YARA_REJECTED

                if get_setting_fn is None:
                    try:
                        from app import _get_setting
                        get_setting_fn = _get_setting
                    except ImportError:
                        get_setting_fn = lambda _k, d='': d

                yara_result = sync_yara_to_db(
                    detections,
                    user_id,
                    username,
                    data_yara=data_yara,
                    data_pending=data_pending,
                    data_rejected=data_rejected,
                    yara_import_mode=yara_mode,
                    get_setting_fn=get_setting_fn,
                )
                log(
                    'Insert YARA rules',
                    'ok',
                    f"mode={yara_mode} added={yara_result.get('yara_added', 0)} "
                    f"pending={yara_result.get('yara_pending_added', 0)} "
                    f"blocked={yara_result.get('yara_blocked', 0)} "
                    f"skipped={yara_result.get('yara_skipped', 0)} "
                    f"invalid={yara_result.get('yara_invalid', 0)}",
                )

        result = {
            'success': True,
            'fetched': len(indicators),
            **ioc_result,
            **yara_result,
        }
        return result
    finally:
        _release_lock()
