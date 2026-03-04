"""IOC submission routes — extracted from app.py."""

import json
import re
import csv
import io
import os
import logging
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Blueprint, request, jsonify
from flask_login import current_user
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from extensions import db
from models import Campaign, IOC, IocHistory, User, ActivityEvent, _utcnow
from utils.decorators import login_required
from utils.validation import validate_ioc, detect_ioc_type, AUTO_DETECT_PATTERNS, PRIORITY_ORDER, REGEX_PATTERNS
from utils.refanger import refanger, sanitize_comment
from utils.ioc_decode import prepare_text_for_ioc_extraction
from utils.validation_warnings import get_ioc_warnings
from utils.validation_messages import MSG_MISSING_FIELDS, MSG_MISSING_FIELDS_TYPE_VALUE, MSG_INVALID_IOC_TYPE, MSG_IOC_EXISTS
from utils.sanity_checks import check_critical as check_sanity_critical, get_sanity_warnings
from constants import IOC_FILES

bp = Blueprint('ioc_bp', __name__)


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


# ---------------------------------------------------------------------------
# Helper functions (used only by routes in this module)
# ---------------------------------------------------------------------------

def parse_ioc_line(line):
    """Parse an IOC line to extract metadata."""
    line = line.strip()
    if not line:
        return None
    
    # Split by '#' to separate IOC from metadata
    parts = line.split('#', 1)
    if len(parts) < 2:
        return None
    
    ioc_value = parts[0].strip()
    metadata = parts[1].strip()
    
    # Parse metadata: Date:{ISO} | User:{user} | Ref:{ticket_id} | Comment:{comment} | EXP:{date}
    result = {
        'ioc': ioc_value,
        'date': None,
        'user': None,
        'ref': None,
        'comment': None,
        'expiration': None
    }
    
    # Extract Date
    date_match = re.search(r'Date:([^|]+)', metadata)
    if date_match:
        result['date'] = date_match.group(1).strip()
    
    # Extract User
    user_match = re.search(r'User:([^|]+)', metadata)
    if user_match:
        result['user'] = user_match.group(1).strip()
    
    # Extract Ref (ticket_id)
    ref_match = re.search(r'Ref:([^|]+)', metadata)
    if ref_match:
        result['ref'] = ref_match.group(1).strip()
    
    # Extract Comment
    comment_match = re.search(r'Comment:([^|]+)', metadata)
    if comment_match:
        result['comment'] = comment_match.group(1).strip()
    
    # Extract Expiration
    exp_match = re.search(r'EXP:([^|]+|NEVER)', metadata)
    if exp_match:
        result['expiration'] = exp_match.group(1).strip()
    
    return result


def _parse_ioc_line_permissive(line):
    """Return a dict with at least ioc, date, user, ref, comment, expiration. Raw lines (no '#') get minimal dict."""
    parsed = parse_ioc_line(line)
    if parsed:
        return parsed
    line = line.strip()
    if not line:
        return None
    ioc_value = line.split('#', 1)[0].strip()
    if not ioc_value:
        return None
    return {
        'ioc': ioc_value,
        'date': None,
        'user': '',
        'ref': '',
        'comment': '',
        'expiration': None
    }


def _refang_text_for_scan(text: str) -> str:
    """Best-effort refang for common IOC defangs inside large pasted text (Paste flow). Aligns with refanger.py patterns."""
    if not text:
        return ''
    t = text
    # Protocol: h-t-t-p(s), hxxp(s)
    t = re.sub(r'h\-t\-t\-p\-s', 'https', t, flags=re.IGNORECASE)
    t = re.sub(r'h\-t\-t\-p(?!\-s)', 'http', t, flags=re.IGNORECASE)
    t = re.sub(r'\bhxxps://', 'https://', t, flags=re.IGNORECASE)
    t = re.sub(r'\bhxxp://', 'http://', t, flags=re.IGNORECASE)
    t = re.sub(r'\bhtp://', 'http://', t, flags=re.IGNORECASE)
    t = re.sub(r'\[\s*:\s*\]', ':', t)
    t = re.sub(r'\[\s*/\s*\]', '/', t)
    t = re.sub(r'\bftp:\s*//', 'ftp://', t, flags=re.IGNORECASE)
    t = re.sub(r'\bsftp:\s*//', 'sftp://', t, flags=re.IGNORECASE)
    # Email @
    t = re.sub(r'\[\s*at\s*\]', '@', t, flags=re.IGNORECASE)
    t = re.sub(r'\(\s*at\s*\)', '@', t, flags=re.IGNORECASE)
    t = re.sub(r'\{\s*at\s*\}', '@', t, flags=re.IGNORECASE)
    t = re.sub(r'\[\s*@\s*\]', '@', t)
    # Dots
    t = t.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
    t = re.sub(r'\{\s*\.\s*\}', '.', t)
    return t


def _extract_iocs_from_text(text: str):
    """
    Extract IOCs from raw text (incl. common defangs).
    Returns list of (value, ioc_type) with priority: URL > Email > IP (v4/v6) > Hash > Domain (deduped by value).
    """
    t = _refang_text_for_scan(text)
    seen = set()
    out = []

    def _add(raw: str, ioc_type: str):
        raw = (raw or '').strip()
        if not raw:
            return
        if ioc_type in ('Domain', 'Email', 'URL'):
            key = raw.lower()
        else:
            key = raw
        if key in seen:
            return
        seen.add(key)
        out.append((raw, ioc_type))

    # URL: with protocol (after refang: http, https, ftp, sftp)
    for m in re.finditer(r'(?:https?|ftp|sftp)://[^\s<>"\']+', t, flags=re.IGNORECASE):
        raw = m.group(0)
        raw = re.sub(r'[\)\]\}\.,;:!?]+$', '', raw)
        _add(raw, 'URL')

    # URL without protocol: domain/path -> https:// (same as TXT/CSV/Single)
    for m in re.finditer(r'(?<![/@])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/[^\s#?]+', t):
        raw = m.group(0)
        raw = re.sub(r'[\)\]\}\.,;:!?]+$', '', raw)
        _add('https://' + raw, 'URL')

    # Email
    for m in re.finditer(AUTO_DETECT_PATTERNS.get('Email', r'$^'), t):
        _add(m.group(0), 'Email')

    # IP v4
    for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', t):
        cand = m.group(0)
        try:
            ipaddress.ip_address(cand)
            _add(cand, 'IP')
        except ValueError:
            continue

    # IP v6 (best-effort candidate scan + ipaddress validation)
    for m in re.finditer(r'\b[0-9A-Fa-f:]{2,}\b', t):
        cand = m.group(0)
        if ':' not in cand or cand.count(':') < 2:
            continue
        try:
            ip_obj = ipaddress.ip_address(cand)
            if ip_obj.version == 6:
                _add(cand, 'IP')
        except ValueError:
            continue

    # Hash (MD5/SHA1/SHA256)
    for m in re.finditer(AUTO_DETECT_PATTERNS.get('Hash', r'$^'), t):
        _add(m.group(0), 'Hash')

    # Domain (avoid emails via pattern negative lookbehind)
    for m in re.finditer(AUTO_DETECT_PATTERNS.get('Domain', r'$^'), t):
        _add(m.group(0), 'Domain')

    return out


def _parse_date_from_staging(date_str):
    """
    Parse date string from staging (preview-txt returns %Y-%m-%dT%H:%M:%S).
    Returns datetime or None if unparseable.
    """
    s = (date_str or '').strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00').split('.')[0])
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, TypeError):
        pass
    for fmt, max_len in (('%Y-%m-%dT%H:%M:%S', 19), ('%Y-%m-%d %H:%M:%S', 19), ('%Y-%m-%d', 10)):
        try:
            dt = datetime.strptime(s[:max_len], fmt)
            return dt.replace(tzinfo=None)
        except (ValueError, TypeError):
            continue
    return None


def _parse_txt_metadata(metadata_raw):
    """
    Parse metadata string per spec: Date (end) -> User 'by X' (end) -> Ticket ID 'N -' (start) -> Comment (remainder).
    Returns dict: created_at (datetime or None), analyst (str or None), ticket_id (str or None), comment (str).
    """
    s = (metadata_raw or '').strip()
    created_at = None
    analyst = None
    ticket_id = None

    # Step A: Date at end — e.g. "1/12/2026 9:47:43 PM" or "12/28/2025"
    date_time_end = re.compile(
        r'(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)\s*$',
        re.IGNORECASE
    )
    date_only_end = re.compile(r'(\d{1,2})/(\d{1,2})/(\d{4})\s*$')
    m = date_time_end.search(s)
    if m:
        try:
            month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
            hour, minute = int(m.group(4)), int(m.group(5))
            sec = int(m.group(6)) if m.group(6) else 0
            ampm = (m.group(7) or '').upper()
            if ampm == 'PM' and hour != 12:
                hour += 12
            elif ampm == 'AM' and hour == 12:
                hour = 0
            created_at = datetime(year, month, day, hour, minute, sec)
        except (ValueError, IndexError):
            pass
        s = s[:m.start()].strip()
    else:
        m = date_only_end.search(s)
        if m:
            try:
                month, day, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
                created_at = datetime(year, month, day)
            except (ValueError, IndexError):
                pass
            s = s[:m.start()].strip()

    # Step B: "by <username>" at end (case-insensitive)
    by_user_end = re.compile(r'\s+by\s+([a-zA-Z0-9_-]+)\s*$', re.IGNORECASE)
    m = by_user_end.search(s)
    if m:
        analyst = m.group(1).strip().lower()
        s = s[:m.start()].strip()

    # Step C: Ticket ID at start — number followed by hyphen (e.g. "45036 - ...")
    ticket_start = re.compile(r'^\s*(\d+)\s*-\s*')
    m = ticket_start.match(s)
    if m:
        ticket_id = m.group(1).strip()
        s = s[m.end():].strip()

    # Step D: Comment = remainder; clean leading/trailing whitespace and stray separators
    comment = re.sub(r'^[\s\-]+|[\s\-]+$', '', s)
    comment = re.sub(r'\s+', ' ', comment).strip()
    return {'created_at': created_at, 'analyst': analyst, 'ticket_id': ticket_id, 'comment': comment}


def _normalize_txt_ioc(ioc_cleaned: str):
    """
    Unified IOC normalization for Submit IOCs (Single, TXT, CSV, Paste).
    If the value looks like 'domain/path' without protocol, normalize to 'https://' + value
    so it is detected as URL. Otherwise return (ioc_cleaned, detect_ioc_type(ioc_cleaned)).
    Call refanger() on raw input before this. Returns (value_to_use, ioc_type or None).
    """
    if not ioc_cleaned:
        return ioc_cleaned, None
    if '/' in ioc_cleaned and not ioc_cleaned.lower().startswith(('http://', 'https://')):
        candidate = 'https://' + ioc_cleaned
        if validate_ioc(candidate, 'URL'):
            return candidate, 'URL'
    ioc_type = detect_ioc_type(ioc_cleaned)
    return ioc_cleaned, ioc_type


def _log_champs_event(event_type, user_id=None, payload=None):
    """Log activity event for Champs ticker and scoring."""
    (_commit_with_retry,) = _from_app('_commit_with_retry')
    try:
        ev = ActivityEvent(
            event_type=event_type,
            user_id=user_id,
            payload=json.dumps(payload) if payload is not None else None,
        )
        db.session.add(ev)
        _commit_with_retry()
    except Exception:
        db.session.rollback()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.route('/api/submit-ioc', methods=['POST'])
@login_required
def submit_ioc():
    """Handle single IOC submission."""
    (
        _api_error, _api_ok, _commit_with_retry, audit_log, _log_ioc_history,
        check_allowlist, get_country_code, calculate_expiration_date, check_ioc_exists,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _auto_ticket_id,
        _capture_champs_before, _detect_champs_changes,
        _data_dir,
    ) = _from_app(
        '_api_error', '_api_ok', '_commit_with_retry', 'audit_log', '_log_ioc_history',
        'check_allowlist', 'get_country_code', 'calculate_expiration_date', 'check_ioc_exists',
        '_create_ioc', '_compute_rare_find_fields',
        '_resolve_analyst_to_user', '_auto_ticket_id',
        '_capture_champs_before', '_detect_champs_changes',
        '_data_dir',
    )
    try:
        data = request.get_json()
        
        value = data.get('value', '').strip()
        ioc_type = data.get('type', '')
        comment = data.get('comment', '')
        assign_to = data.get('user_id') or data.get('analyst')
        resolved = _resolve_analyst_to_user(assign_to) if (assign_to is not None and str(assign_to).strip() != '') else None
        # If assign-to user does not exist, save under current user (avoid invalid analyst names in Champs)
        user_id, username = resolved if resolved else (current_user.id, current_user.username.lower())
        ttl = data.get('ttl', 'Permanent')
        ticket_id = data.get('ticket_id', '').strip() or _auto_ticket_id(user_id)
        campaign_name = (data.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        tags_raw = data.get('tags')
        if isinstance(tags_raw, list):
            tags_list = [str(t).strip() for t in tags_raw if str(t).strip()]
        elif isinstance(tags_raw, str):
            tags_list = [t.strip() for t in tags_raw.split(',') if t.strip()]
        else:
            tags_list = []
        tags_json = json.dumps(tags_list[:50]) if tags_list else '[]'  # cap at 50 tags
        
        # Validation
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': MSG_MISSING_FIELDS}), 400
        
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': MSG_INVALID_IOC_TYPE}), 400
        
        # Apply refanger (auto-fix hxxp->http, [.]->., (.)->., [dot]->.)
        cleaned_value, was_changed = refanger(value)
        value = cleaned_value
        
        # Critical sanity checks (after refanger). Admin may bypass: treat as warning and allow.
        is_blocked, msg = check_sanity_critical(value, ioc_type, _data_dir)
        if is_blocked and not getattr(current_user, 'is_admin', False):
            return jsonify({'success': False, 'message': f'⛔ {msg}'}), 400
        
        # Validate after cleaning
        if not validate_ioc(value, ioc_type):
            return jsonify({'success': False, 'message': f'Invalid {ioc_type} format'}), 400
        
        warnings = get_ioc_warnings(value, ioc_type)
        sanity_warnings = get_sanity_warnings(value, ioc_type)
        warnings.extend(sanity_warnings)
        if is_blocked and getattr(current_user, 'is_admin', False):
            warnings.append(msg)
        
        # Check allowlist (Safety Net) — hard block, no exceptions
        is_blocked, reason = check_allowlist(value, ioc_type)
        if is_blocked:
            return jsonify({
                'success': False,
                'message': f'⛔ Allowlist: Block Prevented! {reason}'
            }), 403
        
        # Prevent duplicate IOCs (case-insensitive)
        if check_ioc_exists(ioc_type, value):
            return jsonify({'success': False, 'message': MSG_IOC_EXISTS}), 409

        rare = _compute_rare_find_fields(ioc_type, value)
        exp_date = calculate_expiration_date(ttl)
        champs_before = _capture_champs_before(user_id, username)
        try:
            db.session.add(_create_ioc(
                ioc_type, value, username, 'single',
                ticket_id=ticket_id, comment=sanitize_comment(comment),
                expiration_date=exp_date, campaign_id=campaign_id,
                user_id=user_id, tags=tags_json, rare=rare,
            ))
            _commit_with_retry()
        except IntegrityError:
            db.session.rollback()
            return _api_error(MSG_IOC_EXISTS, 409)
        except (ValueError, OSError) as e:
            db.session.rollback()
            return _api_error(f'Database error: {str(e)}', 500)
        payload_hist = {}
        if exp_date:
            payload_hist['expiration_date'] = exp_date.isoformat()
        _log_ioc_history(ioc_type, value, 'created', username, payload_hist if payload_hist else None)
        _commit_with_retry()
        cmt = (comment or '').strip() if comment else ''
        comment_preview = (cmt[:80] + '...') if len(cmt) > 80 else cmt
        audit_log('IOC_CREATE', f'type={ioc_type} value={value[:80]} comment="{comment_preview}" campaign={campaign_name or "-"}')
        _log_champs_event('ioc_submit', user_id=user_id, payload={'type': ioc_type, 'value': value[:100]})
        response = {'success': True, 'message': f'{ioc_type} IOC submitted successfully'}
        if was_changed:
            response['auto_corrected'] = True
        if warnings:
            response['warnings'] = warnings
        response.update(_detect_champs_changes(champs_before, user_id, username))
        return jsonify(response)
    except (TypeError, AttributeError) as e:
        return _api_error('Invalid request body or missing JSON', 400)
    except Exception as e:
        logging.exception('submit_ioc failed')
        return _api_error('An unexpected error occurred', 500)


@bp.route('/api/v1/ioc', methods=['POST'])
@login_required
def ingest_ioc():
    """External API endpoint for programmatic IOC ingestion (e.g., MISP integration)."""
    (
        _commit_with_retry, audit_log, check_allowlist, calculate_expiration_date, check_ioc_exists,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _log_ioc_history,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', 'check_allowlist', 'calculate_expiration_date', 'check_ioc_exists',
        '_create_ioc', '_compute_rare_find_fields',
        '_resolve_analyst_to_user', '_log_ioc_history',
    )
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'message': 'Invalid JSON payload'}), 400
        
        ioc_type = data.get('type', '').strip()
        value = data.get('value', '').strip()
        comment = data.get('comment', '')
        username_raw = (data.get('username') or '').strip() or current_user.username
        resolved = _resolve_analyst_to_user(username_raw)
        if resolved:
            user_id_ingest, username = resolved
        else:
            user_id_ingest, username = current_user.id, current_user.username.lower()
        expiration = data.get('expiration', 'Permanent').strip()
        ticket_id = data.get('ticket_id', '').strip()
        
        # Validation
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': MSG_MISSING_FIELDS_TYPE_VALUE}), 400
        
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': f'{MSG_INVALID_IOC_TYPE}. Must be one of: {", ".join(IOC_FILES.keys())}'}), 400
        
        # Apply refanger (input cleaning)
        cleaned_value, was_changed = refanger(value)
        value = cleaned_value
        
        # Validate after cleaning
        if not validate_ioc(value, ioc_type):
            return jsonify({'success': False, 'message': f'Invalid {ioc_type} format'}), 400
        
        # Check allowlist (Safety Net)
        is_blocked, reason = check_allowlist(value, ioc_type)
        if is_blocked:
            return jsonify({
                'success': False,
                'message': f'⛔ CRITICAL ASSET: Block Prevented! {reason}'
            }), 403
        
        if check_ioc_exists(ioc_type, value):
            return jsonify({'success': False, 'message': MSG_IOC_EXISTS}), 409
        if expiration.lower() == 'permanent':
            exp_dt = None
        else:
            try:
                exp_dt = datetime.strptime(expiration, '%Y-%m-%d')
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid expiration date format. Use YYYY-MM-DD or "Permanent"'}), 400
        rare = _compute_rare_find_fields(ioc_type, value)
        try:
            db.session.add(_create_ioc(
                ioc_type, value, username, 'import',
                ticket_id=ticket_id, comment=comment,
                expiration_date=exp_dt, user_id=user_id_ingest, rare=rare,
            ))
            _commit_with_retry()
            payload_hist = {}
            if exp_dt:
                payload_hist['expiration_date'] = exp_dt.isoformat()
            _log_ioc_history(ioc_type, value, 'created', username, payload_hist if payload_hist else None)
            _commit_with_retry()
            cmt = (comment or '').strip()[:80]
            audit_log('IOC_INGEST', f'type={ioc_type} value={value[:80]} comment="{cmt}" analyst={username}')
            return jsonify({
                'success': True,
                'message': f'{ioc_type} IOC ingested successfully',
                'ioc': value,
                'type': ioc_type
            }), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({'success': False, 'message': MSG_IOC_EXISTS}), 409
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/bulk-csv', methods=['POST'])
@login_required
def bulk_csv():
    """Handle bulk CSV intelligence dump."""
    (
        _commit_with_retry, audit_log, _log_ioc_history,
        check_allowlist, calculate_expiration_date,
        _create_ioc, _compute_rare_find_fields,
        _auto_ticket_id,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', '_log_ioc_history',
        'check_allowlist', 'calculate_expiration_date',
        '_create_ioc', '_compute_rare_find_fields',
        '_auto_ticket_id',
    )
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        global_comment = request.form.get('comment', '')
        username = current_user.username.lower()
        ttl = request.form.get('ttl', 'Permanent')
        campaign_name = (request.form.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Stream CSV content line-by-line (avoids loading entire file into memory)
        stream = io.TextIOWrapper(file.stream, encoding='utf-8', errors='replace')
        csv_reader = csv.reader(stream)
        
        # Read header row to detect ticket ID column
        header_row = next(csv_reader, None)
        ticket_id_column_index = None
        if header_row:
            def _norm(s):
                s = (s or '').replace('\ufeff', '').strip().lower()
                return ' '.join(s.split())
            header_lower = [_norm(c) for c in header_row]
            for idx, col in enumerate(header_lower):
                if col in ('reportid', 'ticket_id', 'ref', 'reference', 'ticket', 'report id', 'id') or (col and ('ticket' in col or 'report' in col or col == 'ref')):
                    if ticket_id_column_index is None:
                        ticket_id_column_index = idx
            if ticket_id_column_index is None:
                for idx, col_name in enumerate(header_row):
                    c = _norm(col_name)
                    if c in ('reportid', 'ticket_id', 'ref', 'reference') or (c and ('ticket' in c or 'report' in c)):
                        ticket_id_column_index = idx
                        break
        
        exp_date = calculate_expiration_date(ttl)
        
        # Collect all findings with ticket IDs
        findings = {
            'IP': {},
            'Domain': {},
            'Hash': {},
            'Email': {},
            'URL': {}
        }
        
        # Process every row in the CSV
        for row in csv_reader:
            # Extract ticket ID from the row if column was found
            ticket_id = None
            if ticket_id_column_index is not None and ticket_id_column_index < len(row):
                ticket_id = row[ticket_id_column_index].strip()
                if not ticket_id:
                    ticket_id = None
            
            # Process every cell in the row (decode hex/entities, refang, normalize domain/path -> URL)
            for cell in row:
                if not cell:
                    continue
                expanded_cell = prepare_text_for_ioc_extraction(cell)
                refanged_cell, _ = refanger((expanded_cell or cell).strip())
                if not refanged_cell:
                    continue
                for ioc_type, pattern in AUTO_DETECT_PATTERNS.items():
                    matches = re.findall(pattern, refanged_cell)
                    for match in matches:
                        final_value, final_type = _normalize_txt_ioc(match)
                        if final_type is None:
                            final_type = ioc_type
                            final_value = match
                        if not validate_ioc(final_value, final_type):
                            continue
                        is_blocked, _ = check_allowlist(final_value, final_type)
                        if not is_blocked:
                            if final_value not in findings[final_type]:
                                findings[final_type][final_value] = ticket_id
                        break
        
        comment = sanitize_comment(global_comment)
        csv_fallback_ticket = _auto_ticket_id(current_user.id)
        summary = {}
        total_updated = 0
        total_new = 0
        for ioc_type, ioc_dict in findings.items():
            updated_count = 0
            new_count = 0
            for value, ticket_id in ioc_dict.items():
                ticket_id_val = (ticket_id.strip() if ticket_id else None) or csv_fallback_ticket
                existing = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.lower()).first()
                if existing:
                    existing.comment = comment
                    existing.expiration_date = exp_date
                    existing.ticket_id = ticket_id_val or existing.ticket_id
                    if campaign_id is not None:
                        existing.campaign_id = campaign_id
                    updated_count += 1
                else:
                    rare = _compute_rare_find_fields(ioc_type, value)
                    db.session.add(_create_ioc(
                        ioc_type, value, username, 'csv',
                        ticket_id=ticket_id_val, comment=comment,
                        expiration_date=exp_date, campaign_id=campaign_id,
                        user_id=current_user.id if current_user.is_authenticated else None,
                        rare=rare,
                    ))
                    payload_hist = {}
                    if exp_date:
                        payload_hist['expiration_date'] = exp_date.isoformat()
                    _log_ioc_history(ioc_type, value, 'created', username, payload_hist if payload_hist else None)
                    new_count += 1
            try:
                _commit_with_retry()
            except Exception:
                db.session.rollback()
                raise
            summary[ioc_type] = {'updated': updated_count, 'new': new_count}
            total_updated += updated_count
            total_new += new_count
        
        # Build summary message
        summary_parts = []
        for ioc_type, counts in summary.items():
            if counts['new'] > 0 or counts['updated'] > 0:
                parts = []
                if counts['new'] > 0:
                    parts.append(f"{counts['new']} new")
                if counts['updated'] > 0:
                    parts.append(f"{counts['updated']} updated")
                summary_parts.append(f"{ioc_type}s ({', '.join(parts)})")
        
        message = f"Processed CSV: {', '.join(summary_parts)}" if summary_parts else "No valid IOCs found in CSV"
        fn = (file.filename or '')[:60]
        cmt = (global_comment or '')[:60]
        audit_log('BULK_CSV', f'file={fn} analyst={username} new={total_new} updated={total_updated} comment="{cmt}"')
        
        return jsonify({
            'success': True,
            'message': message,
            'summary': summary,
            'total': total_new + total_updated
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/preview-csv', methods=['POST'])
@login_required
def preview_csv():
    """
    Parse CSV using same logic as bulk_csv; return JSON items for staging (no DB write).
    Accepts: file, username, ttl, comment, optional ticket_id (fallback when CSV has no ticket column).
    For each IOC: existing_permanent=True if DB row exists (any expiration); UI disables Approve and shows "Already exists".
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir',
    )
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        username = current_user.username.lower()
        ttl = request.form.get('ttl', 'Permanent')
        comment = request.form.get('comment', '').strip()
        ticket_id_fallback = request.form.get('ticket_id', '').strip() or _auto_ticket_id(current_user.id)

        if ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(ttl)
            expiration_display = exp_dt.strftime('%Y-%m-%d') if exp_dt else 'Permanent'

        stream = io.StringIO(file.read().decode('utf-8'))
        csv_reader = csv.reader(stream)
        header_row = next(csv_reader, None)
        ticket_id_column_index = None
        if header_row:
            ticket_id_keywords = ['reportid', 'ticket_id', 'ref', 'reference']
            for idx, col_name in enumerate(header_row):
                if col_name.lower().strip() in ticket_id_keywords:
                    ticket_id_column_index = idx
                    break

        # Collect unique IOCs per (type, value), ticket_id from last occurrence (same as bulk_csv)
        ioc_to_ticket = {
            'IP': {}, 'Domain': {}, 'Hash': {}, 'Email': {}, 'URL': {}
        }
        for row in csv_reader:
            ticket_id = None
            if ticket_id_column_index is not None and ticket_id_column_index < len(row):
                ticket_id = row[ticket_id_column_index].strip() or None
            if not ticket_id:
                ticket_id = ticket_id_fallback

            for cell in row:
                if not cell:
                    continue
                expanded_cell = prepare_text_for_ioc_extraction(cell)
                refanged_cell, _ = refanger((expanded_cell or cell).strip())
                if not refanged_cell:
                    continue
                for ioc_type, pattern in AUTO_DETECT_PATTERNS.items():
                    matches = re.findall(pattern, refanged_cell)
                    for match in matches:
                        final_value, final_type = _normalize_txt_ioc(match)
                        if final_type is None:
                            final_type = ioc_type
                            final_value = match
                        if not validate_ioc(final_value, final_type):
                            continue
                        if check_sanity_critical(final_value, final_type, _data_dir)[0] and not getattr(current_user, 'is_admin', False):
                            continue
                        is_blocked, _ = check_allowlist(final_value, final_type)
                        if is_blocked:
                            continue
                        if final_value not in ioc_to_ticket[final_type]:
                            ioc_to_ticket[final_type][final_value] = ticket_id
                        break

        items = []
        for ioc_type, ioc_dict in ioc_to_ticket.items():
            for value, ticket_id in ioc_dict.items():
                existing_permanent = False
                existing_analyst = ''
                existing_comment = ''
                existing_row = IOC.query.filter(
                    IOC.type == ioc_type,
                    func.lower(IOC.value) == value.lower()
                ).first()
                if existing_row:
                    existing_permanent = True
                    existing_analyst = (existing_row.analyst or '')
                    existing_comment = (existing_row.comment or '')

                ticket_id_val = (ticket_id.strip() if ticket_id else None) or ticket_id_fallback
                items.append({
                    'ioc': value,
                    'type': ioc_type,
                    'ticket_id': ticket_id_val or '',
                    'analyst': username,
                    'date': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                    'comment': sanitize_comment(comment) or '',
                    'expiration': expiration_display,
                    'existing_permanent': existing_permanent,
                    'existing_analyst': existing_analyst,
                    'existing_comment': existing_comment
                })

        return jsonify({'success': True, 'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/preview-txt', methods=['POST'])
@login_required
def preview_txt():
    """
    Parse TXT file with smart metadata logic; fill missing fields from form defaults.
    Returns JSON array of { ioc, type, ticket_id, analyst, date, comment } for staging table.
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir',
    )
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        default_analyst = current_user.username.lower()
        default_ticket = request.form.get('default_ticket', '').strip() or _auto_ticket_id(current_user.id)
        default_ttl = request.form.get('default_ttl', 'Permanent')
        default_comment = request.form.get('default_comment', '').strip()

        if default_ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(default_ttl)
            expiration_display = exp_dt.strftime('%Y-%m-%d') if exp_dt else 'Permanent'

        content = file.read().decode('utf-8')
        lines = content.split('\n')
        items = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if '#' in line:
                parts = line.split('#', 1)
                ioc_raw = parts[0].strip()
                metadata_raw = (parts[1] or '').strip()
            else:
                ioc_raw = line
                metadata_raw = ''

            expanded = prepare_text_for_ioc_extraction(ioc_raw)
            extracted = _extract_iocs_from_text(expanded)
            parsed = _parse_txt_metadata(metadata_raw)
            analyst = (parsed['analyst'] or default_analyst).lower()
            ticket_id = parsed['ticket_id'] or default_ticket
            created_at = parsed['created_at'] or datetime.now()
            comment = sanitize_comment(parsed['comment'] or default_comment or '') or ''

            if not extracted:
                ioc_cleaned, _ = refanger(ioc_raw.strip())
                if not ioc_cleaned:
                    continue
                ioc_cleaned, ioc_type = _normalize_txt_ioc(ioc_cleaned)
                if not ioc_type:
                    continue
                extracted = [(ioc_cleaned, ioc_type)]

            for raw_value, ioc_type in extracted:
                ioc_cleaned, _ = refanger(raw_value)
                if not ioc_cleaned:
                    continue
                ioc_cleaned, ioc_type = _normalize_txt_ioc(ioc_cleaned)
                if not ioc_type:
                    continue
                if ioc_type == 'IP':
                    try:
                        ipaddress.ip_address(ioc_cleaned)
                    except ValueError:
                        continue
                else:
                    if not validate_ioc(ioc_cleaned, ioc_type):
                        continue
                if check_sanity_critical(ioc_cleaned, ioc_type, _data_dir)[0] and not getattr(current_user, 'is_admin', False):
                    continue
                is_blocked, _ = check_allowlist(ioc_cleaned, ioc_type)
                if is_blocked:
                    continue

                existing_permanent = False
                existing_analyst = ''
                existing_comment = ''
                existing_row = IOC.query.filter(
                    IOC.type == ioc_type,
                    func.lower(IOC.value) == ioc_cleaned.lower()
                ).first()
                if existing_row:
                    existing_permanent = True
                    existing_analyst = (existing_row.analyst or '')
                    existing_comment = (existing_row.comment or '')

                items.append({
                    'ioc': ioc_cleaned,
                    'type': ioc_type,
                    'ticket_id': ticket_id or '',
                    'analyst': analyst,
                    'date': created_at.strftime('%Y-%m-%dT%H:%M:%S'),
                    'comment': comment,
                    'expiration': expiration_display,
                    'existing_permanent': existing_permanent,
                    'existing_analyst': existing_analyst,
                    'existing_comment': existing_comment
                })

        return jsonify({'success': True, 'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/preview-paste', methods=['POST'])
@login_required
def preview_paste():
    """
    Extract IOCs from pasted text (IPs, domains, URLs, emails, hashes).
    JSON body: { text, default_ticket?, default_ttl?, default_comment? }.
    Returns same format as preview_txt for staging table.
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir',
    )
    try:
        data = request.get_json() or {}
        text = (data.get('text') or '').strip()
        if not text:
            return jsonify({'success': False, 'message': 'No text provided'}), 400
        default_analyst = current_user.username.lower()
        default_ticket = (data.get('default_ticket') or '').strip() or _auto_ticket_id(current_user.id)
        default_ttl = (data.get('default_ttl') or 'Permanent').strip()
        default_comment = (data.get('default_comment') or '').strip()

        if default_ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(default_ttl)
            expiration_display = exp_dt.strftime('%Y-%m-%d') if exp_dt else 'Permanent'

        text_expanded = prepare_text_for_ioc_extraction(text)
        extracted = _extract_iocs_from_text(text_expanded)
        items = []
        for raw_value, ioc_type in extracted:
            ioc_cleaned, _ = refanger(raw_value)
            if not ioc_cleaned:
                continue
            if ioc_type == 'IP':
                try:
                    ipaddress.ip_address(ioc_cleaned)
                except ValueError:
                    continue
            else:
                if not validate_ioc(ioc_cleaned, ioc_type):
                    continue
            if check_sanity_critical(ioc_cleaned, ioc_type, _data_dir)[0] and not getattr(current_user, 'is_admin', False):
                continue
            is_blocked, _ = check_allowlist(ioc_cleaned, ioc_type)
            if is_blocked:
                continue

            existing_permanent = False
            existing_analyst = ''
            existing_comment = ''
            existing_row = IOC.query.filter(
                IOC.type == ioc_type,
                func.lower(IOC.value) == ioc_cleaned.lower()
            ).first()
            if existing_row:
                existing_permanent = True
                existing_analyst = (existing_row.analyst or '')
                existing_comment = (existing_row.comment or '')

            items.append({
                'ioc': ioc_cleaned,
                'type': ioc_type,
                'ticket_id': default_ticket or '',
                'analyst': default_analyst,
                'date': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                'comment': sanitize_comment(default_comment or '') or '',
                'expiration': expiration_display,
                'existing_permanent': existing_permanent,
                'existing_analyst': existing_analyst,
                'existing_comment': existing_comment
            })

        return jsonify({'success': True, 'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/preview-single', methods=['POST'])
@login_required
def preview_single():
    """
    Preview a single IOC for the Single staging table. Returns one item with existing_permanent
    so the UI can show "Already exists" and disable Approve when the IOC is already in the DB.
    JSON body: { type, value, ticket_id?, ttl?, comment? }.
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir',
    )
    try:
        data = request.get_json() or {}
        ioc_type = (data.get('type') or '').strip()
        value_raw = (data.get('value') or '').strip()
        if not value_raw:
            return jsonify({'success': False, 'message': MSG_MISSING_FIELDS_TYPE_VALUE}), 400
        if ioc_type not in IOC_FILES or ioc_type == 'YARA':
            ioc_type = None
        value = None
        expanded = prepare_text_for_ioc_extraction(value_raw)
        extracted = _extract_iocs_from_text(expanded)
        if extracted:
            raw_value, _ = extracted[0]
            val, _ = refanger(raw_value)
            val = (val or '').strip()
            val, detected_type = _normalize_txt_ioc(val)
            if val and detected_type:
                value, ioc_type = val, detected_type
        if value is None:
            val, _ = refanger(value_raw)
            val = (val or '').strip()
            val, detected_type = _normalize_txt_ioc(val)
            if val:
                value = val
                if detected_type is not None:
                    ioc_type = detected_type
        if not value:
            return jsonify({'success': False, 'message': 'Invalid value after refang'}), 400
        if not ioc_type or ioc_type not in IOC_FILES or ioc_type == 'YARA':
            return jsonify({'success': False, 'message': MSG_INVALID_IOC_TYPE}), 400
        if not validate_ioc(value, ioc_type):
            return jsonify({'success': False, 'message': f'Invalid {ioc_type} format'}), 400
        if check_sanity_critical(value, ioc_type, _data_dir)[0] and not getattr(current_user, 'is_admin', False):
            return jsonify({'success': False, 'message': 'Critical/sanity block'}), 400
        is_blocked, _ = check_allowlist(value, ioc_type)
        if is_blocked:
            return jsonify({'success': False, 'message': 'Allowlist block'}), 403
        ticket_id = (data.get('ticket_id') or '').strip() or _auto_ticket_id(current_user.id)
        ttl = (data.get('ttl') or 'Permanent').strip()
        comment = sanitize_comment((data.get('comment') or '').strip() or '') or ''
        if ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(ttl)
            expiration_display = exp_dt.strftime('%Y-%m-%d') if exp_dt else 'Permanent'
        username = current_user.username.lower()
        existing_permanent = False
        existing_analyst = ''
        existing_comment = ''
        existing_row = IOC.query.filter(
            IOC.type == ioc_type,
            func.lower(IOC.value) == value.lower()
        ).first()
        if existing_row:
            existing_permanent = True
            existing_analyst = (existing_row.analyst or '')
            existing_comment = (existing_row.comment or '')
        item = {
            'ioc': value,
            'type': ioc_type,
            'ticket_id': ticket_id or '',
            'analyst': username,
            'date': datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
            'comment': comment,
            'expiration': expiration_display,
            'existing_permanent': existing_permanent,
            'existing_analyst': existing_analyst,
            'existing_comment': existing_comment
        }
        return jsonify({'success': True, 'item': item})
    except Exception as e:
        logging.exception('preview_single failed')
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/submit-staging', methods=['POST'])
@login_required
def submit_staging():
    """Save staged IOC array to DB. Expects JSON: { items: [...], ttl, campaign_name? }. Each item: ioc, type, ticket_id?, analyst, date?, comment?."""
    (
        _commit_with_retry, _log_ioc_history, audit_log,
        check_allowlist, calculate_expiration_date,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _auto_ticket_id,
        _capture_champs_before, _detect_champs_changes,
        _data_dir,
    ) = _from_app(
        '_commit_with_retry', '_log_ioc_history', 'audit_log',
        'check_allowlist', 'calculate_expiration_date',
        '_create_ioc', '_compute_rare_find_fields',
        '_resolve_analyst_to_user', '_auto_ticket_id',
        '_capture_champs_before', '_detect_champs_changes',
        '_data_dir',
    )
    try:
        data = request.get_json() or {}
        items = data.get('items') or []
        ttl = (data.get('ttl') or 'Permanent').strip()
        campaign_name = (data.get('campaign_name') or '').strip() or None
        submission_source = (data.get('source') or 'single').strip()
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id

        champs_before = _capture_champs_before(current_user.id, current_user.username.lower())
        fallback_ticket = _auto_ticket_id(current_user.id)
        summary = {}
        total_updated = 0
        total_new = 0
        for raw in items:
            ioc_value = (raw.get('ioc') or '').strip()
            ioc_type = (raw.get('type') or '').strip()
            if not ioc_value or not ioc_type:
                continue
            if ioc_type not in IOC_FILES or ioc_type == 'YARA':
                continue
            ioc_value, _ = refanger(ioc_value)
            if not validate_ioc(ioc_value, ioc_type):
                continue
            is_critical, _ = check_sanity_critical(ioc_value, ioc_type, _data_dir)
            if is_critical and not getattr(current_user, 'is_admin', False):
                continue
            is_blocked, _ = check_allowlist(ioc_value, ioc_type)
            if is_blocked:
                continue
            analyst_raw = (raw.get('analyst') or '').strip() or 'unknown'
            resolved_user = _resolve_analyst_to_user(analyst_raw)
            if resolved_user:
                user_id, analyst = resolved_user
            else:
                # User not in system: save under current user so Champs shows one entry per analyst
                user_id, analyst = current_user.id, current_user.username.lower()
            ticket_id = (raw.get('ticket_id') or '').strip() or fallback_ticket
            comment = sanitize_comment(raw.get('comment') or '') or None
            date_str = (raw.get('date') or '').strip()
            created_at = _parse_date_from_staging(date_str) or datetime.now()

            exp_str = (raw.get('expiration') or '').strip()
            if exp_str.upper() in ('PERMANENT', 'NEVER'):
                exp_date = None
            elif exp_str:
                try:
                    exp_date = datetime.strptime(exp_str[:10], '%Y-%m-%d')
                except (ValueError, TypeError):
                    exp_date = calculate_expiration_date(ttl)
            else:
                exp_date = calculate_expiration_date(ttl)

            existing = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == ioc_value.lower()).first()
            if existing:
                existing.comment = comment
                existing.expiration_date = exp_date
                existing.ticket_id = ticket_id or existing.ticket_id
                existing.analyst = analyst
                existing.user_id = user_id
                if campaign_id is not None:
                    existing.campaign_id = campaign_id
                total_updated += 1
                summary[ioc_type] = summary.get(ioc_type, {'updated': 0, 'new': 0})
                summary[ioc_type]['updated'] += 1
            else:
                rare = _compute_rare_find_fields(ioc_type, ioc_value)
                db.session.add(_create_ioc(
                    ioc_type, ioc_value, analyst, submission_source,
                    ticket_id=ticket_id, comment=comment,
                    expiration_date=exp_date, created_at=created_at,
                    campaign_id=campaign_id, user_id=user_id, rare=rare,
                ))
                payload_hist = {}
                if exp_date:
                    payload_hist['expiration_date'] = exp_date.isoformat()
                _log_ioc_history(ioc_type, ioc_value, 'created', analyst, payload_hist if payload_hist else None)
                total_new += 1
                summary[ioc_type] = summary.get(ioc_type, {'updated': 0, 'new': 0})
                summary[ioc_type]['new'] += 1

        try:
            _commit_with_retry()
        except Exception:
            db.session.rollback()
            raise

        summary_parts = []
        for ioc_type, counts in summary.items():
            parts = []
            if counts.get('new'):
                parts.append(f"{counts['new']} new")
            if counts.get('updated'):
                parts.append(f"{counts['updated']} updated")
            if parts:
                summary_parts.append(f"{ioc_type}s ({', '.join(parts)})")
        message = f"Imported: {', '.join(summary_parts)}" if summary_parts else "No items imported"
        audit_log('IOC_STAGING_SUBMIT', f'source={submission_source} new={total_new} updated={total_updated} campaign={campaign_name or "-"}')
        resp = {'success': True, 'message': message, 'summary': summary, 'total': total_new + total_updated}
        if total_new > 0:
            resp.update(_detect_champs_changes(champs_before, current_user.id, current_user.username.lower()))
        return jsonify(resp)
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/upload-txt', methods=['POST'])
@login_required
def upload_txt():
    """Handle bulk TXT file upload with smart parsing (log-format aware)."""
    (
        _commit_with_retry, audit_log, _log_ioc_history,
        check_allowlist, calculate_expiration_date,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _auto_ticket_id,
        _capture_champs_before, _detect_champs_changes,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', '_log_ioc_history',
        'check_allowlist', 'calculate_expiration_date',
        '_create_ioc', '_compute_rare_find_fields',
        '_resolve_analyst_to_user', '_auto_ticket_id',
        '_capture_champs_before', '_detect_champs_changes',
    )
    try:
        champs_before = _capture_champs_before(current_user.id, current_user.username.lower())
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        default_ticket_id = request.form.get('ticket_id', '').strip() or _auto_ticket_id(current_user.id)
        username = current_user.username.lower()
        ttl = request.form.get('ttl', 'Permanent')
        campaign_name = (request.form.get('campaign_name') or '').strip() or None
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Stream TXT content line-by-line (avoids loading entire file into memory)
        stream = io.TextIOWrapper(file.stream, encoding='utf-8', errors='replace')
        exp_date = calculate_expiration_date(ttl)
        findings = {'IP': {}, 'Domain': {}, 'Hash': {}, 'Email': {}, 'URL': {}}

        for raw_line in stream:
            line = raw_line.strip()
            if not line:
                continue
            if '#' in line:
                parts = line.split('#', 1)
                ioc_raw = parts[0].strip()
                metadata_raw = (parts[1] or '').strip()
            else:
                ioc_raw = line
                metadata_raw = ''
            if not ioc_raw:
                continue
            parsed = _parse_txt_metadata(metadata_raw)
            analyst_raw = (parsed['analyst'] or username).strip() or username
            resolved_txt = _resolve_analyst_to_user(analyst_raw)
            final_user = (resolved_txt[1] if resolved_txt else username)
            final_date = parsed['created_at'] or datetime.now()
            final_ticket_id = parsed['ticket_id'] or default_ticket_id
            comment_sanitized = sanitize_comment(parsed['comment'] or '')

            expanded = prepare_text_for_ioc_extraction(ioc_raw)
            extracted = _extract_iocs_from_text(expanded)
            if not extracted:
                ioc_cleaned, _ = refanger(ioc_raw.strip())
                if ioc_cleaned:
                    ioc_cleaned, ioc_type = _normalize_txt_ioc(ioc_cleaned)
                    if ioc_type:
                        extracted = [(ioc_cleaned, ioc_type)]

            for raw_value, ioc_type in extracted:
                ioc_cleaned, _ = refanger(raw_value)
                if not ioc_cleaned:
                    continue
                ioc_cleaned, ioc_type = _normalize_txt_ioc(ioc_cleaned)
                if not ioc_type:
                    continue
                if ioc_type == 'IP':
                    try:
                        ipaddress.ip_address(ioc_cleaned)
                    except ValueError:
                        continue
                else:
                    if not validate_ioc(ioc_cleaned, ioc_type):
                        continue
                is_blocked, _ = check_allowlist(ioc_cleaned, ioc_type)
                if is_blocked:
                    continue
                if ioc_cleaned not in findings[ioc_type]:
                    findings[ioc_type][ioc_cleaned] = {
                        'comment': comment_sanitized or None,
                        'user': final_user,
                        'ticket_id': final_ticket_id,
                        'created_at': final_date
                    }
        
        summary = {}
        total_updated = 0
        total_new = 0
        for ioc_type, ioc_dict in findings.items():
            updated_count = 0
            new_count = 0
            for value, meta in ioc_dict.items():
                existing = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.lower()).first()
                if existing:
                    existing.comment = meta['comment']
                    existing.expiration_date = exp_date
                    existing.ticket_id = meta['ticket_id'] or existing.ticket_id
                    if campaign_id is not None:
                        existing.campaign_id = campaign_id
                    updated_count += 1
                else:
                    rare = _compute_rare_find_fields(ioc_type, value)
                    u = meta['user']
                    resolved_bulk_txt = _resolve_analyst_to_user(u)
                    if resolved_bulk_txt:
                        store_user_id, store_analyst = resolved_bulk_txt
                    else:
                        store_user_id = current_user.id if current_user.is_authenticated else None
                        store_analyst = current_user.username.lower()
                    db.session.add(_create_ioc(
                        ioc_type, value, store_analyst, 'txt',
                        ticket_id=meta['ticket_id'], comment=meta['comment'],
                        expiration_date=exp_date, created_at=meta['created_at'],
                        campaign_id=campaign_id, user_id=store_user_id,
                        rare=rare,
                    ))
                    payload_hist = {}
                    if exp_date:
                        payload_hist['expiration_date'] = exp_date.isoformat()
                    _log_ioc_history(ioc_type, value, 'created', store_analyst, payload_hist if payload_hist else None)
                    new_count += 1
            try:
                _commit_with_retry()
            except Exception:
                db.session.rollback()
                raise
            summary[ioc_type] = {'updated': updated_count, 'new': new_count}
            total_updated += updated_count
            total_new += new_count
        
        # Build summary message
        summary_parts = []
        for ioc_type, counts in summary.items():
            if counts['new'] > 0 or counts['updated'] > 0:
                parts = []
                if counts['new'] > 0:
                    parts.append(f"{counts['new']} new")
                if counts['updated'] > 0:
                    parts.append(f"{counts['updated']} updated")
                summary_parts.append(f"{ioc_type}s ({', '.join(parts)})")
        
        message = f"Processed TXT: {', '.join(summary_parts)}" if summary_parts else "No valid IOCs found in TXT"
        fn = (file.filename or '')[:60]
        audit_log('BULK_TXT', f'file={fn} analyst={username} new={total_new} updated={total_updated}')
        
        resp = {
            'success': True,
            'message': message,
            'summary': summary,
            'total': total_new + total_updated
        }
        if total_new > 0:
            resp.update(_detect_champs_changes(champs_before, current_user.id, current_user.username.lower()))
        return jsonify(resp)
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
