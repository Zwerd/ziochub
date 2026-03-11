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

from flask import Blueprint, Response, current_app
from sqlalchemy import func

from extensions import db
from models import IOC
from constants import IOC_FILES
from utils.yara_utils import yara_safe_path
from utils.feed_helpers import strip_url_protocol, format_checkpoint_feed
from utils.validation_messages import MSG_INVALID_IOC_TYPE, MSG_INVALID_FILENAME, MSG_FILE_NOT_FOUND


bp = Blueprint('feeds', __name__, url_prefix='/feed')


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
    now = datetime.now()
    q = IOC.query.filter(
        IOC.type == ioc_type,
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
    created_ts = (row.created_at or now).strftime('%Y-%m-%dT%H:%M:%S.000Z') if row.created_at else now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
    ind_id = _stix_id_for_ioc(row)
    name = f"ZIoCHub {ioc_type}: {val[:50]}" + ('...' if len(val) > 50 else '')
    comment = (row.comment or '')[:200] or None
    return {
        'type': 'indicator',
        'spec_version': '2.1',
        'id': ind_id,
        'created': created_ts,
        'modified': created_ts,
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
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000000Z') if dt.tzinfo is None else dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _feed_stix_objects_page(
    added_after=None,
    offset=0,
    limit=500,
    match_ids=None,
    match_types=None,
    match_spec_versions=None,
):
    """
    Return one page of STIX 2.1 Indicator objects for TAXII 2.1 Get Objects.
    Uses stable ordering (created_at, id). Supports added_after and match[] filters.
    Returns (objects, has_more, first_date_added, last_date_added).
    first_date_added/last_date_added are ISO timestamp strings or None when no objects.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    q = IOC.query.filter(
        IOC.type != 'YARA',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    )
    if added_after is not None:
        q = q.filter(IOC.created_at >= added_after)
    if match_types is not None and 'indicator' not in match_types:
        # We only have indicators; if client asked for other types, return empty
        return [], False, None, None
    if match_spec_versions is not None and '2.1' not in match_spec_versions:
        return [], False, None, None
    q = q.order_by(IOC.created_at, IOC.id)
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
    first_dt = rows[0].created_at if rows else None
    last_dt = rows[-1].created_at if rows else None
    first_ts = _stix_date_added_iso(first_dt) if first_dt else None
    last_ts = _stix_date_added_iso(last_dt) if last_dt else None
    return objects, has_more, first_ts, last_ts


def _feed_stix_object_by_id(object_id):
    """
    Return a single STIX 2.1 Indicator for the given TAXII/STIX object id, or None.
    Also returns date_added (ISO str) for that object for TAXII headers.
    """
    if not object_id or not isinstance(object_id, str) or not object_id.strip().startswith('indicator--'):
        return None, None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    q = IOC.query.filter(
        IOC.type != 'YARA',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).order_by(IOC.created_at, IOC.id)
    for row in q.all():
        if _stix_id_for_ioc(row) == object_id.strip():
            ind = _stix_indicator_from_row(row, now)
            if ind:
                ts = _stix_date_added_iso(row.created_at) if row.created_at else None
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
):
    """
    Return one page of TAXII 2.1 manifest records (id, date_added, version, media_type).
    Same filters and ordering as _feed_stix_objects_page.
    Returns (manifest_objects, has_more, first_date_added, last_date_added).
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    media_type = 'application/stix+json;version=2.1'
    q = IOC.query.filter(
        IOC.type != 'YARA',
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    )
    if added_after is not None:
        q = q.filter(IOC.created_at >= added_after)
    if match_types is not None and 'indicator' not in match_types:
        return [], False, None, None
    if match_spec_versions is not None and '2.1' not in match_spec_versions:
        return [], False, None, None
    q = q.order_by(IOC.created_at, IOC.id)
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
        created_ts = (row.created_at or now).strftime('%Y-%m-%dT%H:%M:%S.000Z') if row.created_at else now.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        manifest_objects.append({
            'id': _stix_id_for_ioc(row),
            'date_added': _stix_date_added_iso(row.created_at) if row.created_at else created_ts,
            'version': created_ts,
            'media_type': media_type,
        })
    first_dt = rows[0].created_at if rows else None
    last_dt = rows[-1].created_at if rows else None
    first_ts = _stix_date_added_iso(first_dt) if first_dt else None
    last_ts = _stix_date_added_iso(last_dt) if last_dt else None
    return manifest_objects, has_more, first_ts, last_ts


def _feed_stix_object_versions(object_id):
    """
    Return list of version entries for one object (TAXII 2.1 Get Object Versions).
    ZIoCHub has one version per IOC (created = modified). Returns (versions_list, first_date_added, last_date_added) or (None, None, None) if not found.
    """
    ind, date_added = _feed_stix_object_by_id(object_id)
    if ind is None:
        return None, None, None
    created_ts = ind.get('created') or ind.get('modified')
    versions = [{'id': ind['id'], 'date_added': date_added or created_ts, 'version': created_ts}]
    return versions, date_added, date_added


# --- YARA feeds (specific paths first) ---

@bp.route('/yara-list', methods=['GET'])
def feed_yara_list():
    """Plain text list of all .yar filenames in DATA_YARA (one per line)."""
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


@bp.route('/yara-content/<path:filename>', methods=['GET'])
def feed_yara_content(filename):
    """Raw content of a .yar file. Path traversal safe."""
    safe, filepath = _yara_safe_path(filename)
    if safe is None:
        return Response(MSG_INVALID_FILENAME, mimetype='text/plain', status=400)
    if not os.path.isfile(filepath):
        return Response(MSG_FILE_NOT_FOUND, mimetype='text/plain', status=404)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return Response(content, mimetype='text/plain')
    except Exception as e:
        return Response(f"Error: {e}", mimetype='text/plain', status=500)


# --- STIX 2.x feed (TAXII/STIX format) ---

@bp.route('/stix', methods=['GET'])
@bp.route('/stix/<ioc_type>', methods=['GET'])
def feed_stix(ioc_type=None):
    """STIX 2.1 JSON bundle of active IOCs. /feed/stix = all types; /feed/stix/ip = IP only, etc."""
    hash_length = None
    if ioc_type:
        mapped_type, hash_length = _feed_resolve_ioc_type(ioc_type)
        if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
            return Response(json.dumps({'error': 'Invalid type'}), mimetype='application/json', status=404)
        ioc_type = mapped_type
    bundle = _feed_stix_bundle(ioc_type_filter=ioc_type, hash_length=hash_length)
    return Response(
        json.dumps(bundle, ensure_ascii=False),
        mimetype='application/json',
        headers={'Content-Disposition': 'inline', 'X-Content-Type-Options': 'nosniff'}
    )


# --- Generic IOC feed ---

@bp.route('/<ioc_type>')
def feed_ioc(ioc_type):
    """Single generic feed: /feed/ip, /feed/domain, /feed/url, /feed/md5, /feed/sha1, /feed/sha256, /feed/hash."""
    mapped_type, hash_length = _feed_resolve_ioc_type(ioc_type)
    if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
        return Response(MSG_INVALID_IOC_TYPE, mimetype='text/plain', status=404)
    return _feed_plain_response(_feed_ioc_plain(mapped_type, hash_length))


@bp.route('/pa/<ioc_type>', methods=['GET'])
def feed_pa(ioc_type):
    """Palo Alto feed: /feed/pa/ip, /feed/pa/domain, etc."""
    mapped_type, hash_length = _feed_resolve_ioc_type(ioc_type)
    if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
        return Response(MSG_INVALID_IOC_TYPE, mimetype='text/plain', status=404)
    formatter = _pa_url_formatter if mapped_type == 'URL' else _pa_plain_formatter
    return _feed_ioc_formatted(mapped_type, formatter, hash_length=hash_length)


@bp.route('/cp/<ioc_type>', methods=['GET'])
def feed_cp(ioc_type):
    """Checkpoint feed (CSV): /feed/cp/ip, /feed/cp/domain, etc."""
    mapped_type, hash_length = _feed_resolve_ioc_type(ioc_type)
    if mapped_type is None or mapped_type not in IOC_FILES or mapped_type == 'YARA':
        return Response(MSG_INVALID_IOC_TYPE, mimetype='text/plain', status=404)
    formatter = lambda rows: format_checkpoint_feed(rows, mapped_type)
    return _feed_ioc_formatted(mapped_type, formatter, hash_length=hash_length)


@bp.route('/esa/email', methods=['GET'])
def feed_esa_email():
    """Cisco ESA email feed: comma-separated list of active email IOCs."""
    return _feed_ioc_formatted('Email', _esa_comma_formatter)


# --- Trellix ePO feeds ---

def _epo_feed_ticket_ids():
    """Distinct ticket_ids that have at least one active Hash IOC."""
    now = datetime.now()
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
    try:
        names = _epo_feed_ticket_ids()
        return Response('\n'.join(names) + ('\n' if names else ''), mimetype='text/plain')
    except Exception:
        return Response('', mimetype='text/plain')


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
    now = datetime.now()
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
