"""
Feed routes: YARA list/content, generic IOC feeds, PA, CP, ESA, ePO, STIX 2.x.
Register with url_prefix='/feed' so routes are /feed/yara-list, /feed/ip, etc.
"""
import io
import json
import os
import re
import csv
import uuid
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, request
from sqlalchemy import func

from extensions import db
from models import IOC
from constants import IOC_FILES
from utils.yara_utils import yara_safe_path
from utils.feed_helpers import strip_url_protocol, format_checkpoint_feed
from utils.validation_messages import MSG_INVALID_IOC_TYPE, MSG_INVALID_FILENAME, MSG_FILE_NOT_FOUND
from utils.feed_cache import serve_feed_cached


bp = Blueprint('feeds', __name__, url_prefix='/feed')


def _feeds_allowed():
    """Return True if feeds are enabled (feeds_public_enabled). When False, callers should return 503."""
    try:
        from app import _get_setting
        return _get_setting('feeds_public_enabled', 'true').strip().lower() == 'true'
    except Exception:
        return True


@bp.before_request
def _require_feeds_enabled():
    """When feeds_public_enabled is false, return 503 for all /feed/* requests."""
    if _feeds_allowed():
        return None
    return Response(
        'Feeds are not available. Enable "Feeds and TAXII publicly available" in Admin Settings.',
        status=503,
        mimetype='text/plain',
        headers={'Retry-After': '60'},
    )


@bp.after_request
def _record_feed_connection_telemetry(response):
    """Track last successful /feed pull per client IP + path (Feed Pulse → Connections; TAXII uses same telemetry)."""
    try:
        from utils.integration_telemetry import record_feed_pull_if_ok
        record_feed_pull_if_ok(response)
    except Exception:
        pass
    return response


def _get_data_yara():
    """Data YARA directory from app config (set by app on init)."""
    return current_app.config.get('DATA_YARA') or ''


def _yara_safe_path(filename):
    """Return (safe_basename, full_path) if path is under DATA_YARA; else (None, None)."""
    return yara_safe_path(filename, _get_data_yara())


# Max rows per feed type to avoid loading unbounded data (e.g. 50k IPs)
FEED_IOC_MAX_ROWS = 50000


def _feed_ioc_rows(ioc_type, hash_length=None, max_rows=None):
    """Return list of active (non-expired) IOC rows for the given type. Optionally filter Hash by length. Capped at max_rows (default FEED_IOC_MAX_ROWS) for efficiency."""
    if max_rows is None:
        max_rows = FEED_IOC_MAX_ROWS
    # Stored timestamps are UTC-naive (see models._utcnow). Always compare using UTC-naive "now".
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    q = IOC.query.filter(
        IOC.type == ioc_type,
        IOC.revoked.is_(False),
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    )
    rows = q.limit(max_rows).all()
    if hash_length is not None:
        rows = [r for r in rows if len((r.value or '').strip()) == hash_length]
    return rows


def _feed_ioc_plain(ioc_type, hash_length=None):
    """Return list of IOC value strings for the given type (and optional hash length)."""
    rows = _feed_ioc_rows(ioc_type, hash_length)
    return [(r.value or '').strip() for r in rows]


def _feed_plain_response(rows_or_values):
    """Format rows or list of value strings as plain newline-separated response."""
    if not rows_or_values:
        values = []
    elif hasattr(rows_or_values[0], 'value'):
        values = [(r.value or '').strip() for r in rows_or_values]
    else:
        values = list(rows_or_values)
    return Response('\n'.join(values) + '\n', mimetype='text/plain')


def _feed_ioc_formatted(ioc_type, formatter, hash_length=None):
    """Return Response with feed content: get rows via _feed_ioc_rows, then formatter(rows) -> str."""
    rows = _feed_ioc_rows(ioc_type, hash_length)
    return Response(formatter(rows), mimetype='text/plain')


def _pa_plain_formatter(rows):
    """Palo Alto: newline-separated values."""
    values = [(r.value or '').strip() for r in rows]
    return '\n'.join(values) + '\n'


def _pa_url_formatter(rows):
    """Palo Alto URL: newline-separated with http(s):// stripped."""
    values = [strip_url_protocol((r.value or '').strip()) or '' for r in rows]
    return '\n'.join(values) + '\n'


def _esa_comma_formatter(rows):
    """Cisco ESA: comma-separated values."""
    values = [(r.value or '').strip() for r in rows]
    return ','.join(values)


def _feed_resolve_ioc_type(ioc_type_raw):
    """Resolve path segment to (mapped_type, hash_length). Returns (None, None) if invalid."""
    key = ioc_type_raw.strip().lower()
    mapping = {
        'ip': ('IP', None), 'ipaddress': ('IP', None), 'ip_address': ('IP', None),
        'domain': ('Domain', None),
        'url': ('URL', None),
        'md5': ('Hash', 32), 'sha1': ('Hash', 40), 'sha256': ('Hash', 64),
        'hash': ('Hash', None),
        'email': ('Email', None),
    }
    return mapping.get(key, (key if key in IOC_FILES else None, None))


def _feed_cp_resolve_ioc_type(ioc_type_raw):
    """Checkpoint CSV: IP, Domain, URL, Hash (all algorithms), or Hash filtered by type.

    - /feed/cp/hash-all supported hashes (MD5, SHA-1, SHA-256, SHA-512).
    - /feed/cp/md5, /sha1, /sha256, /sha2-only that algorithm (sha2 = SHA-256).
    Email is not supported here (use /feed/esa/email or /feed/email).
    """
    key = (ioc_type_raw or '').strip().lower()
    mapping = {
        'ip': ('IP', None), 'ipaddress': ('IP', None), 'ip_address': ('IP', None),
        'domain': ('Domain', None),
        'url': ('URL', None),
        'hash': ('Hash', None),
        'md5': ('Hash', 32),
        'sha1': ('Hash', 40),
        'sha256': ('Hash', 64),
        'sha2': ('Hash', 64),
    }
    return mapping.get(key, (None, None))


def _stix_escape_pattern_value(value):
    """Escape single quotes for STIX pattern value (use \\' inside quoted value)."""
    if value is None:
        return ''
    return (value or '').replace('\\', '\\\\').replace("'", "\\'")


def _stix_indicator_pattern(ioc_type, value):
    """Return STIX 2.1 pattern string for one IOC. Raises ValueError if type unsupported."""
    v = _stix_escape_pattern_value((value or '').strip())
    if not v:
        raise ValueError('empty value')
    if ioc_type == 'IP':
        if ':' in v:
            return f"[ipv6-addr:value = '{v}']"
        return f"[ipv4-addr:value = '{v}']"
    if ioc_type == 'Domain':
        return f"[domain-name:value = '{v}']"
    if ioc_type == 'URL':
        return f"[url:value = '{v}']"
    if ioc_type == 'Email':
        return f"[email-addr:value = '{v}']"
    if ioc_type == 'Hash':
        n = len(v)
        if n == 32:
            return f"[file:hashes.'MD5' = '{v}']"
        if n == 40:
            return f"[file:hashes.'SHA-1' = '{v}']"
        if n == 64:
            return f"[file:hashes.'SHA-256' = '{v}']"
        if n == 128:
            return f"[file:hashes.'SHA-512' = '{v}']"
        return f"[file:hashes.'SHA-256' = '{v}']"  # fallback
    raise ValueError(f'unsupported type {ioc_type}')


# Deterministic STIX id per IOC so TAXII Get-by-ID and Manifest are stable across requests.
STIX_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, 'ziochub.taxii.stix')


def _stix_id_for_ioc(row):
    """Return deterministic STIX 2.1 indicator id for an IOC row (stable across requests)."""
    return f"indicator--{uuid.uuid5(STIX_ID_NAMESPACE, f'ioc.{row.id}').hex}"


def _stix_indicator_from_row(row, now=None):
    """Build one STIX 2.1 Indicator dict from an IOC row. Returns None if value/pattern invalid."""
    if now is None:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
    ioc_type = row.type
    val = (row.value or '').strip()
    if not val:
        return None
    try:
        pattern = _stix_indicator_pattern(ioc_type, val)
    except ValueError:
        return None
    def _as_utc_naive(dt):
        """
        Normalize a datetime into UTC-naive.
        - aware -> convert to UTC, drop tzinfo
        - naive -> assume it already represents UTC (best-effort for legacy rows)
        """
        if dt is None:
            return None
        try:
            if getattr(dt, 'tzinfo', None) is not None and dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except Exception:
            pass
        return dt

    def _stix_ts(dt_utc_naive):
        """Return ISO-8601 UTC with 'Z' and millisecond precision for STIX."""
        if dt_utc_naive is None:
            return None
        aware = dt_utc_naive.replace(tzinfo=timezone.utc)
        # 2026-04-27T12:34:56.789Z
        return aware.isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    created_dt = _as_utc_naive(getattr(row, 'created_at', None)) or now
    modified_dt = _as_utc_naive(getattr(row, 'modified_at', None) or getattr(row, 'revoked_at', None)) or created_dt
    # Guard: ensure modified never precedes created in emitted STIX.
    if modified_dt < created_dt:
        modified_dt = created_dt
    created_ts = _stix_ts(created_dt)
    modified_ts = _stix_ts(modified_dt)
    ind_id = _stix_id_for_ioc(row)
    name = f"ZIoCHub {ioc_type}: {val[:50]}" + ('...' if len(val) > 50 else '')
    comment = (row.comment or '')[:200] or None
    return {
        'type': 'indicator',
        'spec_version': '2.1',
        'id': ind_id,
        'created': created_ts,
        'modified': modified_ts,
        **({'revoked': True} if bool(getattr(row, 'revoked', False)) else {}),
        'name': name,
        'description': comment,
        'pattern_type': 'stix',
        'pattern': pattern,
        'indicator_types': ['malicious-activity'],
        'valid_from': created_ts,
    }


def _feed_stix_bundle(ioc_type_filter=None, hash_length=None):
    """Build STIX 2.1 Bundle (JSON) of Indicator objects for active IOCs."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    types_to_fetch = [ioc_type_filter] if ioc_type_filter else [t for t in IOC_FILES if t != 'YARA']
    objects = []
    for ioc_type in types_to_fetch:
        if ioc_type not in IOC_FILES or ioc_type == 'YARA':
            continue
        rows = _feed_ioc_rows(ioc_type, hash_length=hash_length)
        for row in rows:
            ind = _stix_indicator_from_row(row, now)
            if ind:
                objects.append(ind)
    bundle_id = f"bundle--{uuid.uuid4()}"
    return {'type': 'bundle', 'id': bundle_id, 'objects': objects}


def _stix_date_added_iso(dt):
    """Format datetime as TAXII timestamp (ISO 8601 with microsecond precision)."""
    if dt is None:
        return None
    # TAXII expects UTC timestamps. Stored datetimes are UTC-naive; treat naive as UTC.
    try:
        if getattr(dt, 'tzinfo', None) is not None and dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        pass
    return dt.replace(tzinfo=timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _feed_stix_objects_page(
    added_after=None,
    offset=0,
    limit=500,
    match_ids=None,
    match_types=None,
    match_spec_versions=None,
    include_revoked: bool = False,
):
    """
    Return one page of STIX 2.1 Indicator objects for TAXII 2.1 Get Objects.
    Uses stable ordering (created_at, id). Supports added_after and match[] filters.
    Returns (objects, has_more, first_date_added, last_date_added).
    first_date_added/last_date_added are ISO timestamp strings or None when no objects.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    q = IOC.query.filter(IOC.type != 'YARA')
    if include_revoked:
        # Include revoked objects so TAXII clients can synchronize removals.
        # Expired-but-not-revoked should not be emitted as active, so we include:
        #   active OR revoked
        q = q.filter(db.or_(
            IOC.revoked.is_(True),
            IOC.expiration_date.is_(None),
            IOC.expiration_date > now,
        ))
    else:
        q = q.filter(
            IOC.revoked.is_(False),
            db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now),
        )
    if added_after is not None:
        q = q.filter(IOC.modified_at >= added_after)
    if match_types is not None and 'indicator' not in match_types:
        # We only have indicators; if client asked for other types, return empty
        return [], False, None, None
    if match_spec_versions is not None and '2.1' not in match_spec_versions:
        return [], False, None, None
    q = q.order_by(IOC.modified_at, IOC.id)
    if match_ids is not None and match_ids:
        want = set(match_ids)
        # Must resolve STIX id -> row; no DB column so we scan in order and filter
        all_rows = q.all()
        rows = [r for r in all_rows if _stix_id_for_ioc(r) in want]
        rows = rows[offset:offset + limit + 1]
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
    else:
        rows = q.offset(offset).limit(limit + 1).all()
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
    objects = []
    for row in rows:
        ind = _stix_indicator_from_row(row, now)
        if ind:
            objects.append(ind)
    first_dt = (rows[0].modified_at or rows[0].created_at) if rows else None
    last_dt = (rows[-1].modified_at or rows[-1].created_at) if rows else None
    first_ts = _stix_date_added_iso(first_dt) if first_dt else None
    last_ts = _stix_date_added_iso(last_dt) if last_dt else None
    return objects, has_more, first_ts, last_ts


def _feed_stix_object_by_id(object_id, *, include_revoked: bool = False):
    """
    Return a single STIX 2.1 Indicator for the given TAXII/STIX object id, or None.
    Also returns date_added (ISO str) for that object for TAXII headers.
    """
    if not object_id or not isinstance(object_id, str) or not object_id.strip().startswith('indicator--'):
        return None, None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    q = IOC.query.filter(IOC.type != 'YARA')
    if include_revoked:
        q = q.filter(db.or_(
            IOC.revoked.is_(True),
            IOC.expiration_date.is_(None),
            IOC.expiration_date > now,
        ))
    else:
        q = q.filter(
            IOC.revoked.is_(False),
            db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now),
        )
    q = q.order_by(IOC.modified_at, IOC.id)
    for row in q.all():
        if _stix_id_for_ioc(row) == object_id.strip():
            ind = _stix_indicator_from_row(row, now)
            if ind:
                dt = row.modified_at or row.created_at
                ts = _stix_date_added_iso(dt) if dt else None
                return ind, ts
            break
    return None, None


def _feed_stix_manifest_page(
    added_after=None,
    offset=0,
    limit=500,
    match_ids=None,
    match_types=None,
    match_spec_versions=None,
    include_revoked: bool = False,
):
    """
    Return one page of TAXII 2.1 manifest records (id, date_added, version, media_type).
    Same filters and ordering as _feed_stix_objects_page.
    Returns (manifest_objects, has_more, first_date_added, last_date_added).
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    media_type = 'application/stix+json;version=2.1'
    q = IOC.query.filter(IOC.type != 'YARA')
    if include_revoked:
        q = q.filter(db.or_(
            IOC.revoked.is_(True),
            IOC.expiration_date.is_(None),
            IOC.expiration_date > now,
        ))
    else:
        q = q.filter(
            IOC.revoked.is_(False),
            db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now),
        )
    if added_after is not None:
        q = q.filter(IOC.modified_at >= added_after)
    if match_types is not None and 'indicator' not in match_types:
        return [], False, None, None
    if match_spec_versions is not None and '2.1' not in match_spec_versions:
        return [], False, None, None
    q = q.order_by(IOC.modified_at, IOC.id)
    if match_ids is not None and match_ids:
        want = set(match_ids)
        all_rows = q.all()
        rows = [r for r in all_rows if _stix_id_for_ioc(r) in want]
        rows = rows[offset:offset + limit + 1]
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
    else:
        rows = q.offset(offset).limit(limit + 1).all()
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
    manifest_objects = []
    for row in rows:
        created_dt = _as_utc_naive(getattr(row, 'created_at', None)) or now
        modified_dt = _as_utc_naive(getattr(row, 'modified_at', None) or getattr(row, 'revoked_at', None)) or created_dt
        if modified_dt < created_dt:
            modified_dt = created_dt
        created_ts = _stix_ts(created_dt)
        modified_ts = _stix_ts(modified_dt)
        manifest_objects.append({
            'id': _stix_id_for_ioc(row),
            'date_added': _stix_date_added_iso(modified_dt) if modified_dt else created_ts,
            'version': modified_ts,
            'media_type': media_type,
        })
    first_dt = (rows[0].modified_at or rows[0].created_at) if rows else None
    last_dt = (rows[-1].modified_at or rows[-1].created_at) if rows else None
    first_ts = _stix_date_added_iso(first_dt) if first_dt else None
    last_ts = _stix_date_added_iso(last_dt) if last_dt else None
    return manifest_objects, has_more, first_ts, last_ts


def _feed_stix_object_versions(object_id, *, include_revoked: bool = False):
    """
    Return list of version entries for one object (TAXII 2.1 Get Object Versions).
    ZIoCHub has one version per IOC (created = modified). Returns (versions_list, first_date_added, last_date_added) or (None, None, None) if not found.
    """
    ind, date_added = _feed_stix_object_by_id(object_id, include_revoked=include_revoked)
    if ind is None:
        return None, None, None
    version_ts = ind.get('modified') or ind.get('created')
    versions = [{'id': ind['id'], 'date_added': date_added or version_ts, 'version': version_ts}]
    return versions, date_added, date_added


# --- YARA feeds (specific paths first) ---

@bp.route('/yara-list', methods=['GET'])
def feed_yara_list():
    """Plain text list of all .yar filenames in DATA_YARA (one per line)."""
    def build():
        try:
            data_yara = _get_data_yara()
            if not os.path.isdir(data_yara):
                return Response("", mimetype='text/plain')
            names = []
            for name in sorted(os.listdir(data_yara)):
                if not name.lower().endswith('.yar'):
                    continue
                fp = os.path.join(data_yara, name)
                if os.path.isfile(fp):
                    names.append(name)
            return Response(('\n'.join(names) + ('\n' if names else '')), mimetype='text/plain')
        except Exception as e:
            return Response(f"Error: {e}", mimetype='text/plain', status=500)

    return serve_feed_cached('yara-list', build)


@bp.route('/yara-content/<path:filename>', methods=['GET'])
def feed_yara_content(filename):
    """Raw content of a .yar file. Path traversal safe."""
    safe, filepath = _yara_safe_path(filename)
    if safe is None:
        return Response(MSG_INVALID_FILENAME, mimetype='text/plain', status=400)
    if not os.path.isfile(filepath):
        return Response(MSG_FILE_NOT_FOUND, mimetype='text/plain', status=404)

    def build():
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            return Response(content, mimetype='text/plain')
        except Exception as e:
            return Response(f"Error: {e}", mimetype='text/plain', status=500)

    return serve_feed_cached(f'yara-content:{safe}', build)


# --- STIX 2.x feed (TAXII/STIX format) ---

@bp.route('/stix', methods=['GET'])
@bp.route('/stix/<ioc_type>', methods=['GET'])
def feed_stix(ioc_type=None):
    """STIX 2.1 JSON bundle of active IOCs. /feed/stix = all types; /feed/stix/ip = IP only, etc."""
    hash_length = None
    path_suffix = 'all'
    if ioc_type:
        path_suffix = (ioc_type or '').strip().lower() or 'all'
        mapped_type, hash_length = _feed_resolve_ioc_type(ioc_type)
        if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
            return Response(json.dumps({'error': 'Invalid type'}), mimetype='application/json', status=404)
        ioc_type = mapped_type

    def build():
        bundle = _feed_stix_bundle(ioc_type_filter=ioc_type, hash_length=hash_length)
        return Response(
            json.dumps(bundle, ensure_ascii=False),
            mimetype='application/json',
            headers={'Content-Disposition': 'inline', 'X-Content-Type-Options': 'nosniff'}
        )

    return serve_feed_cached(f'stix:{path_suffix}', build)


# --- Generic IOC feed ---

@bp.route('/<ioc_type>')
def feed_ioc(ioc_type):
    """Single generic feed: /feed/ip, /feed/domain, /feed/url, /feed/md5, /feed/sha1, /feed/sha256, /feed/hash."""
    mapped_type, hash_length = _feed_resolve_ioc_type(ioc_type)
    if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
        return Response(MSG_INVALID_IOC_TYPE, mimetype='text/plain', status=404)
    seg = (ioc_type or '').strip().lower()

    def build():
        return _feed_plain_response(_feed_ioc_plain(mapped_type, hash_length))

    return serve_feed_cached(f'plain:{seg}', build)


@bp.route('/pa/<ioc_type>', methods=['GET'])
def feed_pa(ioc_type):
    """Palo Alto feed: /feed/pa/ip, /feed/pa/domain, etc."""
    mapped_type, hash_length = _feed_resolve_ioc_type(ioc_type)
    if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
        return Response(MSG_INVALID_IOC_TYPE, mimetype='text/plain', status=404)
    seg = (ioc_type or '').strip().lower()
    formatter = _pa_url_formatter if mapped_type == 'URL' else _pa_plain_formatter

    def build():
        return _feed_ioc_formatted(mapped_type, formatter, hash_length=hash_length)

    return serve_feed_cached(f'pa:{seg}', build)


@bp.route('/cp/<ioc_type>', methods=['GET'])
def feed_cp(ioc_type):
    """Checkpoint feed (CSV): /cp/ip, /domain, /url, /hash (all hashes), /md5, /sha1, /sha256 or /sha2 (per-type)."""
    mapped_type, hash_length = _feed_cp_resolve_ioc_type(ioc_type)
    if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
        return Response(MSG_INVALID_IOC_TYPE, mimetype='text/plain', status=404)
    seg = (ioc_type or '').strip().lower()
    formatter = lambda rows: format_checkpoint_feed(rows, mapped_type)

    def build():
        return _feed_ioc_formatted(mapped_type, formatter, hash_length=hash_length)

    return serve_feed_cached(f'cp:{seg}', build)


@bp.route('/esa/email', methods=['GET'])
def feed_esa_email():
    """Cisco ESA email feed: comma-separated list of active email IOCs."""
    def build():
        return _feed_ioc_formatted('Email', _esa_comma_formatter)

    return serve_feed_cached('esa:email', build)


# --- Trellix ePO feeds ---

def _epo_feed_ticket_ids():
    """Distinct ticket_ids that have at least one active Hash IOC."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ids = set()
    for r in IOC.query.filter(
        IOC.type == 'Hash',
        IOC.ticket_id.isnot(None),
        IOC.ticket_id != '',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).with_entities(IOC.ticket_id).distinct().all():
        if r[0] and (r[0] or '').strip():
            ids.add((r[0] or '').strip())
    return sorted(ids)


@bp.route('/epo/files-list', methods=['GET'])
def feed_epo_files_list():
    """Trellix ePO: list of ticket_id values that have at least one hash. One per line."""
    def build():
        try:
            names = _epo_feed_ticket_ids()
            return Response('\n'.join(names) + ('\n' if names else ''), mimetype='text/plain')
        except Exception:
            return Response('', mimetype='text/plain')

    return serve_feed_cached('epo:files-list', build)


def _epo_feed_rows_for_ticket(ticket_id, now):
    """Yield (ticket_id, md5, sha1, sha256) for ePO CSV: one row per Hash IOC."""
    for ioc in IOC.query.filter(
        IOC.type == 'Hash',
        func.lower(IOC.ticket_id) == ticket_id.lower(),
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).order_by(IOC.id).all():
        val = (ioc.value or '').strip()
        if not val:
            continue
        n = len(val)
        if n == 32:
            yield (ticket_id, val, '', '')
        elif n == 40:
            yield (ticket_id, '', val, '')
        elif n == 64:
            yield (ticket_id, '', '', val)


@bp.route('/epo/<ticket_id>', methods=['GET'])
def feed_epo_file(ticket_id):
    """Trellix ePO: CSV for one ticket_id from Hash IOCs in DB."""
    if not ticket_id or not re.match(r'^[a-zA-Z0-9._-]+$', ticket_id):
        return Response("Invalid ticket id", mimetype='text/plain', status=400)
    cache_key = f'epo:ticket:{ticket_id.strip().lower()}'

    def build():
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['All File Names', 'MD5 Hash', 'SHA-1 Hash', 'SHA-256 Hash'])
        for row in _epo_feed_rows_for_ticket(ticket_id, now):
            writer.writerow(list(row))
        return Response(
            output.getvalue(),
            mimetype='text/plain; charset=utf-8',
            headers={'Content-Disposition': 'inline', 'X-Content-Type-Options': 'nosniff'}
        )

    return serve_feed_cached(cache_key, build)
