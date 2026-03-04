"""
Feed routes: YARA list/content, generic IOC feeds, PA, CP, ESA, ePO.
Register with url_prefix='/feed' so routes are /feed/yara-list, /feed/ip, etc.
"""
import io
import os
import re
import csv
from datetime import datetime

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


def _feed_ioc_rows(ioc_type, hash_length=None):
    """Return list of active (non-expired) IOC rows for the given type. Optionally filter Hash by length."""
    now = datetime.now()
    rows = IOC.query.filter(
        IOC.type == ioc_type,
        db.or_(IOC.expiration_date.is_(None), IOC.expiration_date > now)
    ).all()
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
