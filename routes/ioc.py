"""IOC submission routes - extracted from app.py."""

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
from utils.validation import validate_ioc, detect_ioc_type, AUTO_DETECT_PATTERNS, REGEX_PATTERNS
from utils.refanger import refanger, sanitize_comment
from utils.ioc_decode import prepare_text_for_ioc_extraction
from utils.validation_warnings import get_ioc_warnings
from utils.validation_messages import MSG_MISSING_FIELDS, MSG_MISSING_FIELDS_TYPE_VALUE, MSG_INVALID_IOC_TYPE, MSG_IOC_EXISTS
from utils.sanity_checks import check_critical as check_sanity_critical, get_sanity_warnings
from constants import IOC_FILES
from utils.tags import normalize_tags_from_input
from utils.tags import parse_allowed_tags_setting, enforce_allowed_tags
from utils.upload_text_encoding import decode_uploaded_text_bytes

bp = Blueprint('ioc_bp', __name__)


def _ioc_created_history_payload(
    *,
    entered_by: str,
    assigned_to: str,
    comment=None,
    ticket_id=None,
    expiration_date=None,
    reactivated: bool = False,
    campaign_name=None,
    tags_list=None,
) -> dict:
    """Build IocHistory payload for event_type='created' (shown in Search → History modal)."""
    payload = {
        'entered_by': (entered_by or '').strip(),
        'assigned_to': (assigned_to or '').strip(),
    }
    cmt = sanitize_comment(comment) if comment else ''
    if cmt:
        payload['comment'] = cmt
    tid = (ticket_id or '').strip()
    if tid:
        payload['ticket_id'] = tid
    if expiration_date is not None:
        if hasattr(expiration_date, 'isoformat'):
            payload['expiration_date'] = expiration_date.isoformat()
        else:
            s = str(expiration_date).strip()
            if s:
                payload['expiration_date'] = s[:10] if len(s) >= 10 else s
    if reactivated:
        payload['reactivated'] = True
    cn = (campaign_name or '').strip()
    if cn:
        payload['campaign'] = cn
    if tags_list:
        payload['tags'] = [str(t) for t in tags_list if t is not None and str(t).strip()]
    return payload


def _log_sanity_warning_history(_log_ioc_history_fn, ioc_type: str, value: str, warnings_list: list[str]):
    """
    Record a sanity warning in IOC history so future searches show the system concern.
    Stored as event_type='sanity_warning' by username='system'.
    """
    try:
        items = [w.strip() for w in (warnings_list or []) if isinstance(w, str) and w.strip()]
        if not items:
            return
        msg = 'sanity check failed: ' + ' | '.join(items)
        _log_ioc_history_fn(ioc_type, value, 'sanity_warning', 'system', {'message': msg, 'warnings': items})
    except Exception:
        # Never block submission on history logging failures
        return


def _log_ioc_reactivation_history_if_needed(
    _log_ioc_history_fn,
    was_active_before: bool,
    ioc_type: str,
    value: str,
    analyst: str,
    exp_date,
    entered_by: str,
    *,
    comment=None,
    ticket_id=None,
    campaign_name=None,
    tags_list=None,
):
    """
    After apply_ioc_submission_to_existing_row: if the row was inactive (revoked or expired),
    append a 'created' IocHistory row with reactivated=True — same contract as /api/submit-ioc.
    Skips when the row was already active (metadata-only refresh).
    """
    if was_active_before:
        return
    try:
        payload_hist = _ioc_created_history_payload(
            entered_by=entered_by,
            assigned_to=analyst,
            comment=comment,
            ticket_id=ticket_id,
            expiration_date=exp_date,
            reactivated=True,
            campaign_name=campaign_name,
            tags_list=tags_list,
        )
        _log_ioc_history_fn(ioc_type, value, 'created', analyst, payload_hist)
    except Exception:
        logging.exception('_log_ioc_reactivation_history_if_needed failed')


def _from_app(*names):
    import app as _app
    return tuple(getattr(_app, n) for n in names)


def _schedule_ioc_push_from_submission(**kwargs):
    """Fire-and-forget IOC push to configured HTTP targets (background thread)."""
    try:
        from flask import current_app
        from utils.ioc_push import schedule_ioc_push_after_create, ioc_context_from_submission
        ctx = ioc_context_from_submission(**kwargs)
        schedule_ioc_push_after_create(current_app._get_current_object(), ctx)
        _schedule_auxiliary_vendor_integrations([ctx])
    except Exception as e:
        logging.warning('IOC push schedule failed: %s', e)


def _schedule_auxiliary_vendor_integrations(contexts):
    """Cortex XDR + Google SecOps outbound (Integrations), same IOC context as HTTP push."""
    if not contexts:
        return
    try:
        from flask import current_app
        from utils.outbound_ioc import schedule_auxiliary_vendor_integrations

        schedule_auxiliary_vendor_integrations(current_app._get_current_object(), contexts)
    except Exception as e:
        logging.warning('Auxiliary vendor integrations schedule failed: %s', e)


def _schedule_ioc_push_batch(contexts):
    if not contexts:
        return
    try:
        from flask import current_app
        from utils.ioc_push import schedule_ioc_push_batch as _batch
        _batch(current_app._get_current_object(), contexts)
        _schedule_auxiliary_vendor_integrations(contexts)
    except Exception as e:
        logging.warning('IOC push batch schedule failed: %s', e)


def _schedule_esa_from_submission(**kwargs):
    try:
        from flask import current_app
        from utils.cisco_esa import schedule_esa_dictionary_after_submission
        schedule_esa_dictionary_after_submission(current_app._get_current_object(), **kwargs)
    except Exception as e:
        logging.warning('ESA dictionary schedule failed: %s', e)


def _schedule_esa_batch(contexts):
    if not contexts:
        return
    try:
        from flask import current_app
        from utils.cisco_esa import schedule_esa_dictionary_batch
        schedule_esa_dictionary_batch(current_app._get_current_object(), contexts)
    except Exception as e:
        logging.warning('ESA dictionary batch schedule failed: %s', e)


def _sanity_should_block_else_warn(is_blocked: bool, is_admin: bool, mode: str) -> tuple[bool, bool]:
    """
    Given critical sanity result and settings, return (should_block, should_warn).
    block_all: block everyone, show reason. block_non_admin: block non-admin, admin gets warning. warn_all: warn everyone, no block.
    """
    mode = (mode or 'block_non_admin').strip().lower()
    if mode not in ('block_all', 'block_non_admin', 'warn_all'):
        mode = 'block_non_admin'
    if not is_blocked:
        return False, False
    if mode == 'block_all':
        return True, False
    if mode == 'block_non_admin':
        return not is_admin, is_admin
    return False, True  # warn_all


def _preview_staging_sanity_summary(
    value: str,
    ioc_type: str,
    *,
    is_admin: bool,
    sanity_mode: str,
    data_dir: str,
) -> str:
    """
    Short text for Submit IOC staging tables: critical warn (when applicable) + get_sanity_warnings,
    joined for display (max ~260 chars).
    """
    is_crit, crit_msg = check_sanity_critical(value, ioc_type, data_dir)
    _, should_warn = _sanity_should_block_else_warn(is_crit, is_admin, sanity_mode)
    bits: list[str] = []
    if should_warn and crit_msg:
        cm = crit_msg.strip()
        if cm:
            bits.append(cm)
    for w in get_sanity_warnings(value, ioc_type):
        w = (w or '').strip()
        if w and w not in bits:
            bits.append(w)
    if not bits:
        return ''
    s = ' · '.join(bits[:4])
    if len(s) > 260:
        return s[:257] + '…'
    return s


def _tags_governance(_get_setting):
    """Return (restricted_enabled, allowed_tags_list, allow_suggest)."""
    restricted = (_get_setting('tags_restricted_enabled', 'false') or 'false').strip().lower() == 'true'
    allow_suggest = (_get_setting('tags_allow_suggest', 'true') or 'true').strip().lower() == 'true'
    allowed = parse_allowed_tags_setting(_get_setting('allowed_tags', '[]'))
    return restricted, allowed, allow_suggest


def _validate_tags_or_reject(tags_list, _get_setting):
    """
    Enforce admin-allowed tags if enabled. Returns (tags_list_valid, error_response_or_none).
    """
    try:
        restricted, allowed, allow_suggest = _tags_governance(_get_setting)
        if not restricted or not allowed:
            return tags_list, None
        valid, invalid = enforce_allowed_tags(tags_list or [], allowed)
        if invalid:
            invalid = sorted(set(invalid))
            msg = 'Invalid tag(s). Please select from the allowed tags list.'
            return tags_list, (jsonify({
                'success': False,
                'message': msg,
                'invalid_tags': invalid,
                'suggest_allowed': bool(allow_suggest),
            }), 400)
        return valid, None
    except Exception:
        return tags_list, None


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

    def _split_glued_urls(raw_url: str) -> list[str]:
        """
        If multiple schemes are glued together without whitespace (e.g. 'http://a/xxxhttps://b/y'),
        split into separate URL candidates at every subsequent scheme occurrence.
        """
        s = (raw_url or '').strip()
        if not s:
            return []
        # Find all scheme occurrences; keep the first as-is, split at later ones.
        scheme_re = re.compile(r'(?i)(?:https?|ftp|sftp)://')
        starts = [m.start() for m in scheme_re.finditer(s)]
        if not starts:
            return [s]
        # Only split when we have a second scheme not at position 0.
        splits = [i for i in starts if i > 0]
        if not splits:
            return [s]
        parts = []
        idxs = [0] + splits + [len(s)]
        for a, b in zip(idxs, idxs[1:]):
            part = s[a:b].strip()
            if part:
                parts.append(part)
        return parts

    # URL: with protocol (after refang: http, https, ftp, sftp)
    for m in re.finditer(r'(?:https?|ftp|sftp)://[^\s<>"\']+', t, flags=re.IGNORECASE):
        raw = m.group(0)
        for part in _split_glued_urls(raw):
            part = re.sub(r'[\)\]\}\.,;:!?]+$', '', part)
            _add(part, 'URL')

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


def _extract_atomic_ioc_candidates(fragment: str) -> list[tuple[str, str]]:
    """
    One TXT line prefix (before #) or one CSV cell as a single IOC candidate.
    Returns 0 or 1 (value, type) pairs — no scanning inside URLs for extra domains/hashes.
    Caller should pass text already passed through prepare_text_for_ioc_extraction when applicable.
    """
    s = (fragment or '').replace('\ufeff', '').strip()
    if not s:
        return []
    ioc_cleaned, _ = refanger(s)
    ioc_cleaned = (ioc_cleaned or '').strip()
    if not ioc_cleaned:
        return []
    ioc_cleaned, ioc_type = _normalize_txt_ioc(ioc_cleaned)
    if not ioc_type:
        return []
    if ioc_type == 'IP':
        try:
            ipaddress.ip_address(ioc_cleaned)
        except ValueError:
            return []
    else:
        if not validate_ioc(ioc_cleaned, ioc_type):
            return []
    return [(ioc_cleaned, ioc_type)]


# Column titles that indicate row 1 is a spreadsheet header (not an IOC line)
_CSV_KNOWN_HEADER_LABELS = frozenset({
    'ioc', 'iocvalue', 'ioc_value', 'value', 'values', 'indicator', 'indicators', 'type', 'ioctype',
    'ioc_type', 'ioc type', 'domain', 'url', 'hash', 'email', 'ip', 'ticket', 'ticketid', 'ticket_id',
    'ticket id', 'ref', 'reference', 'reportid', 'report_id', 'report id', 'id', 'description', 'comment',
    'source', 'confidence', 'ttl', 'tags', 'severity', 'firstseen', 'lastseen', 'threat',
})


def _cell_looks_like_ioc_value(cell: str) -> bool:
    """Heuristic: cell content looks like an IOC (not a column name)."""
    s = (cell or '').replace('\ufeff', '').strip()
    if not s:
        return False
    if re.search(r'(?i)(?:https?|ftp|sftp)://|hxxp|h\*\*p|h-t-t-p', s):
        return True
    if '//' in s and not s.lower().startswith(('ioc', 'url', 'ref')):
        return True
    # domain.tld/path-common in IOC lists without scheme
    if re.search(
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/[^\s]+',
        s,
    ):
        return True
    if re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', s):
        return True
    if re.search(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', s):
        return True
    if '@' in s and '.' in (s.split('@')[-1] or ''):
        return True
    return False


def _row_looks_like_column_header_row(row: list) -> bool:
    """True if any non-empty cell matches a typical CSV column title."""
    for cell in row:
        c = (cell or '').replace('\ufeff', '').strip().lower()
        if not c:
            continue
        compact = re.sub(r'[\s_-]+', '', c)
        if compact in _CSV_KNOWN_HEADER_LABELS or c in _CSV_KNOWN_HEADER_LABELS:
            return True
    return False


def _csv_first_row_is_data_not_header(row: list) -> bool:
    """
    If True, row 1 is treated as IOC data (same as other rows).
    If False, row 1 is treated as a header row (column names) and skipped for IOC extraction.
    """
    if not row:
        return True
    if any(_cell_looks_like_ioc_value(c) for c in row):
        return True
    if _row_looks_like_column_header_row(row):
        return False
    # Ambiguous (e.g. single bare domain): prefer data so we never drop the first line of a headerless dump.
    return True


def _extract_iocs_from_csv_cell(cell: str) -> list:
    """
    One CSV cell → at most one IOC row (whole cell normalized/classified).
    Does not mine substrings inside URLs (unlike Paste, which uses _extract_iocs_from_text).
    """
    if not (cell or '').strip():
        return []
    cell = (cell or '').replace('\ufeff', '').strip()
    expanded = prepare_text_for_ioc_extraction(cell)
    fragment = ((expanded if expanded else cell) or '').strip()
    if not fragment:
        return []
    return _extract_atomic_ioc_candidates(fragment)


def _preview_staging_dedup_key(ioc_type: str, ioc_cleaned: str):
    """Key for deduplicating preview rows; aligns with case-insensitive IOC match in DB."""
    return (ioc_type, (ioc_cleaned or '').strip().lower())


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


def _staging_date_display(val):
    """Return ISO-style date string for staging 'date' field. Handles datetime or str (no strftime on str)."""
    if val is None:
        return _utcnow().strftime('%Y-%m-%dT%H:%M:%S')
    if hasattr(val, 'strftime'):
        return val.strftime('%Y-%m-%dT%H:%M:%S')
    if isinstance(val, str):
        return val[:19] if len(val) >= 19 else (val or _utcnow().strftime('%Y-%m-%dT%H:%M:%S'))
    return _utcnow().strftime('%Y-%m-%dT%H:%M:%S')


def _format_expiration_display(exp_dt):
    """Return expiration string for UI. Handles datetime or str (avoid strftime on str)."""
    if exp_dt is None:
        return 'Permanent'
    if hasattr(exp_dt, 'strftime'):
        return exp_dt.strftime('%Y-%m-%d')
    if isinstance(exp_dt, str):
        return exp_dt[:10] if len(exp_dt) >= 10 else exp_dt
    return 'Permanent'


def _parse_txt_metadata(metadata_raw):
    """
    Parse metadata string per spec: Date (end) -> User 'by X' (end) -> Ticket ID 'N -' (start) -> Comment (remainder).
    Returns dict: created_at (datetime or None), analyst (str or None), ticket_id (str or None), comment (str).
    """
    s = (metadata_raw or '').strip()
    created_at = None
    analyst = None
    ticket_id = None

    # Step A: Date at end - e.g. "1/12/2026 9:47:43 PM" or "12/28/2025"
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
    by_user_end = re.compile(r'\s+by\s+([a-zA-Z0-9_.-]+)\s*$', re.IGNORECASE)
    m = by_user_end.search(s)
    if m:
        analyst = m.group(1).strip().lower()
        s = s[:m.start()].strip()

    # Step B2: analyst at start of metadata (e.g. "analyst1 comment" or "analyst1 | comment") so TXT with team names is attributed correctly
    if analyst is None and s:
        analyst_start = re.compile(r'^\s*([a-zA-Z0-9_.-]+)\s*[|\-:\s]')
        m = analyst_start.match(s)
        if m:
            analyst = m.group(1).strip().lower()
            s = s[m.end():].strip()

    # Step C: Ticket ID at start - number followed by hyphen (e.g. "45036 - ...")
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
        apply_ioc_submission_to_existing_row,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _auto_ticket_id,
        _capture_champs_before, _detect_champs_changes,
        _data_dir, _get_setting,
    ) = _from_app(
        '_api_error', '_api_ok', '_commit_with_retry', 'audit_log', '_log_ioc_history',
        'check_allowlist', 'get_country_code', 'calculate_expiration_date', 'check_ioc_exists',
        'apply_ioc_submission_to_existing_row',
        '_create_ioc', '_compute_rare_find_fields',
        '_resolve_analyst_to_user', '_auto_ticket_id',
        '_capture_champs_before', '_detect_champs_changes',
        '_data_dir', '_get_setting',
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
        tags_list = normalize_tags_from_input(data.get('tags'))
        tags_list, tags_err = _validate_tags_or_reject(tags_list, _get_setting)
        if tags_err is not None:
            return tags_err[0], tags_err[1]
        tags_json = json.dumps(tags_list) if tags_list else '[]'
        
        # Validation
        if not value or not ioc_type:
            return jsonify({'success': False, 'message': MSG_MISSING_FIELDS}), 400
        
        if ioc_type not in IOC_FILES:
            return jsonify({'success': False, 'message': MSG_INVALID_IOC_TYPE}), 400
        
        # Apply refanger (auto-fix hxxp->http, [.]->., (.)->., [dot]->.)
        cleaned_value, was_changed = refanger(value)
        value = cleaned_value
        
        # Critical sanity checks (after refanger). Mode: block_all / block_non_admin / warn_all.
        is_blocked, msg = check_sanity_critical(value, ioc_type, _data_dir)
        mode = _get_setting('sanity_check_mode', 'block_non_admin')
        is_admin = getattr(current_user, 'is_admin', False)
        should_block, should_warn = _sanity_should_block_else_warn(is_blocked, is_admin, mode)
        if should_block:
            return jsonify({'success': False, 'message': f'⛔ {msg}'}), 400
        
        # Validate after cleaning
        if not validate_ioc(value, ioc_type):
            return jsonify({'success': False, 'message': f'Invalid {ioc_type} format'}), 400
        
        warnings = get_ioc_warnings(value, ioc_type)
        sanity_warnings = get_sanity_warnings(value, ioc_type)
        warnings.extend(sanity_warnings)
        if should_warn:
            warnings.append(msg)
        
        # Check allowlist (Safety Net) - hard block, no exceptions
        is_blocked, reason = check_allowlist(value, ioc_type)
        if is_blocked:
            return jsonify({
                'success': False,
                'message': f'⛔ Allowlist: Block Prevented! {reason}'
            }), 403
        
        # Block only if the same type+value is already an active IOC (revoked/expired rows are reactivated below).
        if check_ioc_exists(ioc_type, value):
            return jsonify({'success': False, 'message': MSG_IOC_EXISTS}), 409

        rare = _compute_rare_find_fields(ioc_type, value)
        exp_date = calculate_expiration_date(ttl)
        champs_before = _capture_champs_before(user_id, username)
        reactivated = False
        try:
            existing = IOC.query.filter(
                IOC.type == ioc_type,
                func.lower(IOC.value) == value.strip().lower(),
            ).first()
            if existing:
                apply_ioc_submission_to_existing_row(
                    existing,
                    ioc_type,
                    value,
                    username,
                    'single',
                    ticket_id=ticket_id,
                    comment=sanitize_comment(comment),
                    expiration_date=exp_date,
                    campaign_id=campaign_id,
                    user_id=user_id,
                    tags=tags_json,
                    rare=rare,
                )
                reactivated = True
                _commit_with_retry()
            else:
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
        payload_hist = _ioc_created_history_payload(
            entered_by=current_user.username or '',
            assigned_to=username,
            comment=comment,
            ticket_id=ticket_id,
            expiration_date=exp_date,
            reactivated=reactivated,
            campaign_name=campaign_name,
            tags_list=tags_list,
        )
        _log_ioc_history(ioc_type, value, 'created', username, payload_hist)
        _log_sanity_warning_history(
            _log_ioc_history,
            ioc_type,
            value,
            (sanity_warnings or []) + ([msg] if should_warn and msg else []),
        )
        _commit_with_retry()
        cmt = (comment or '').strip() if comment else ''
        comment_preview = (cmt[:80] + '...') if len(cmt) > 80 else cmt
        audit_log('IOC_CREATE', f'type={ioc_type} value={value[:80]} comment="{comment_preview}" campaign={campaign_name or "-"}')
        _log_champs_event('ioc_submit', user_id=user_id, payload={'type': ioc_type, 'value': value[:100]})
        if ioc_type == 'Hash':
            try:
                _get_setting = _from_app('_get_setting')[0]
                if _get_setting('dxl_enabled', 'false').lower() == 'true':
                    config_path = _get_setting('dxl_config_path', '').strip()
                    if config_path:
                        from utils.dxl_tie import push_hash_to_tie
                        push_hash_to_tie(config_path, value, audit_log)
            except Exception as dxl_err:
                logging.warning('DXL push after submit_ioc failed: %s', dxl_err)
        # MISP push: send IOC to MISP when enabled (SOC uses ZIoCHub but feeds MISP; comment pushed if option on).
        # Skip push when analyst is the MISP sync user to avoid loop: MISP → sync into ZIoCHub (analyst=misp_sync) → push back to MISP.
        try:
            _get_setting = _from_app('_get_setting')[0]
            misp_sync_user = (_get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip().lower()
            if _get_setting('misp_push_enabled', 'false').lower() == 'true' and username.lower() != misp_sync_user:
                url = _get_setting('misp_url', '').strip()
                api_key = _get_setting('misp_api_key', '').strip()
                if url and api_key:
                    verify_ssl = _get_setting('misp_verify_ssl', 'false').lower() == 'true'
                    include_comment = _get_setting('misp_push_include_comment', 'true').lower() == 'true'
                    event_id_str = _get_setting('misp_push_default_event_id', '').strip()
                    event_id = int(event_id_str) if event_id_str.isdigit() else None
                    from utils.misp_push import push_ioc_to_misp
                    cmt = (sanitize_comment(comment) or '').strip() if comment else ''
                    ok, msg = push_ioc_to_misp(
                        ioc_type, value, cmt or None,
                        event_id=event_id, url=url, api_key=api_key, verify_ssl=verify_ssl,
                        include_comment=include_comment,
                    )
                    if not ok:
                        logging.warning('MISP push after submit_ioc failed: %s', msg)
        except Exception as misp_err:
            logging.warning('MISP push after submit_ioc failed: %s', misp_err)
        try:
            _schedule_ioc_push_from_submission(
                ioc_type=ioc_type,
                value=value,
                analyst=username,
                ticket_id=ticket_id,
                comment=sanitize_comment(comment) if comment else None,
                expiration_date=exp_date,
                campaign_id=campaign_id,
                tags_json=tags_json,
                submission_method='single',
                user_id=user_id,
            )
        except Exception as push_err:
            logging.warning('IOC push after submit_ioc failed: %s', push_err)
        try:
            _schedule_esa_from_submission(
                ioc_type=ioc_type,
                value=value,
                analyst=username,
                ticket_id=ticket_id,
                comment=sanitize_comment(comment) if comment else None,
                expiration_date=exp_date,
                campaign_id=campaign_id,
                tags_json=tags_json,
                submission_method='single',
                user_id=user_id,
            )
        except Exception as esa_err:
            logging.warning('ESA dictionary after submit_ioc failed: %s', esa_err)
        refresh_champ_score_for_user = _from_app('refresh_champ_score_for_user')[0]
        refresh_champ_score_for_user(user_id)
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
        apply_ioc_submission_to_existing_row,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _log_ioc_history,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', 'check_allowlist', 'calculate_expiration_date', 'check_ioc_exists',
        'apply_ioc_submission_to_existing_row',
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
        reactivated_ingest = False
        try:
            existing = IOC.query.filter(
                IOC.type == ioc_type,
                func.lower(IOC.value) == value.strip().lower(),
            ).first()
            if existing:
                apply_ioc_submission_to_existing_row(
                    existing,
                    ioc_type,
                    value,
                    username,
                    'import',
                    ticket_id=ticket_id,
                    comment=comment,
                    expiration_date=exp_dt,
                    campaign_id=None,
                    user_id=user_id_ingest,
                    tags='[]',
                    rare=rare,
                )
                reactivated_ingest = True
            else:
                db.session.add(_create_ioc(
                    ioc_type, value, username, 'import',
                    ticket_id=ticket_id, comment=comment,
                    expiration_date=exp_dt, user_id=user_id_ingest, rare=rare,
                ))
            _commit_with_retry()
            entered_by = current_user.username if (current_user and current_user.is_authenticated) else 'API'
            payload_hist = _ioc_created_history_payload(
                entered_by=entered_by,
                assigned_to=username,
                comment=comment,
                ticket_id=ticket_id,
                expiration_date=exp_dt,
                reactivated=reactivated_ingest,
            )
            _log_ioc_history(ioc_type, value, 'created', username, payload_hist)
            _commit_with_retry()
            cmt = (comment or '').strip()[:80]
            audit_log('IOC_INGEST', f'type={ioc_type} value={value[:80]} comment="{cmt}" analyst={username}')
            if ioc_type == 'Hash':
                try:
                    _get_setting = _from_app('_get_setting')[0]
                    if _get_setting('dxl_enabled', 'false').lower() == 'true':
                        config_path = _get_setting('dxl_config_path', '').strip()
                        if config_path:
                            from utils.dxl_tie import push_hash_to_tie
                            push_hash_to_tie(config_path, value, audit_log)
                except Exception as dxl_err:
                    logging.warning('DXL push after ingest_ioc failed: %s', dxl_err)
            try:
                from utils.integration_telemetry import record_api_ioc_ingest
                record_api_ioc_ingest()
            except Exception:
                pass
            try:
                _schedule_ioc_push_from_submission(
                    ioc_type=ioc_type,
                    value=value,
                    analyst=username,
                    ticket_id=ticket_id,
                    comment=comment if comment else None,
                    expiration_date=exp_dt,
                    campaign_id=None,
                    tags_json='[]',
                    submission_method='import',
                    user_id=user_id_ingest,
                )
            except Exception as push_err:
                logging.warning('IOC push after ingest_ioc failed: %s', push_err)
            try:
                _schedule_esa_from_submission(
                    ioc_type=ioc_type,
                    value=value,
                    analyst=username,
                    ticket_id=ticket_id,
                    comment=comment if comment else None,
                    expiration_date=exp_dt,
                    campaign_id=None,
                    tags_json='[]',
                    submission_method='import',
                    user_id=user_id_ingest,
                )
            except Exception as esa_err:
                logging.warning('ESA dictionary after ingest_ioc failed: %s', esa_err)
            if user_id_ingest:
                refresh_champ_score_for_user = _from_app('refresh_champ_score_for_user')[0]
                refresh_champ_score_for_user(user_id_ingest)
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
        apply_ioc_submission_to_existing_row,
        _create_ioc, _compute_rare_find_fields,
        _auto_ticket_id, _data_dir, _get_setting,
        ioc_row_is_active,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', '_log_ioc_history',
        'check_allowlist', 'calculate_expiration_date',
        'apply_ioc_submission_to_existing_row',
        '_create_ioc', '_compute_rare_find_fields',
        '_auto_ticket_id', '_data_dir', '_get_setting',
        'ioc_row_is_active',
    )
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        global_comment = request.form.get('comment', '')
        username = current_user.username.lower()
        ttl = request.form.get('ttl', 'Permanent')
        campaign_name = (request.form.get('campaign_name') or '').strip() or None
        tags_list = normalize_tags_from_input(
            request.form.get('tags') or request.form.get('tags_for_all') or ''
        )
        tags_list, tags_err = _validate_tags_or_reject(tags_list, _get_setting)
        if tags_err is not None:
            return tags_err[0], tags_err[1]
        tags_json = json.dumps(tags_list) if tags_list else '[]'
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400

        sanity_mode = _get_setting('sanity_check_mode', 'block_non_admin')
        is_admin = getattr(current_user, 'is_admin', False)

        # Read full CSV; do not treat line 1 as a header when it is IOC data (headerless lists).
        text = decode_uploaded_text_bytes(file.read())
        stream = io.StringIO(text)
        csv_reader = csv.reader(stream)
        all_rows = list(csv_reader)
        ticket_id_column_index = None
        if not all_rows:
            data_rows = []
        elif _csv_first_row_is_data_not_header(all_rows[0]):
            data_rows = all_rows
        else:
            header_row = all_rows[0]
            data_rows = all_rows[1:]
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
        
        # Process every data row in the CSV
        for row in data_rows:
            # Extract ticket ID from the row if column was found
            ticket_id = None
            if ticket_id_column_index is not None and ticket_id_column_index < len(row):
                ticket_id = row[ticket_id_column_index].strip()
                if not ticket_id:
                    ticket_id = None
            
            # Process every cell: one IOC per cell (no substring mining inside URLs)
            for cell in row:
                cell = (cell or '').replace('\ufeff', '').strip()
                if not cell:
                    continue
                for raw_value, ioc_type in _extract_iocs_from_csv_cell(cell):
                    final_value, final_type = _normalize_txt_ioc(raw_value)
                    if final_type is None:
                        final_type = ioc_type
                        final_value = raw_value
                    if not validate_ioc(final_value, final_type):
                        continue
                    is_crit, _ = check_sanity_critical(final_value, final_type, _data_dir)
                    if _sanity_should_block_else_warn(is_crit, is_admin, sanity_mode)[0]:
                        continue
                    is_blocked, _ = check_allowlist(final_value, final_type)
                    if not is_blocked:
                        if final_value not in findings[final_type]:
                            findings[final_type][final_value] = ticket_id

        comment = sanitize_comment(global_comment)
        csv_fallback_ticket = _auto_ticket_id(current_user.id)
        from utils.ioc_push import ioc_context_from_submission
        summary = {}
        total_updated = 0
        total_new = 0
        new_iocs_for_push = []
        for ioc_type, ioc_dict in findings.items():
            updated_count = 0
            new_count = 0
            for value, ticket_id in ioc_dict.items():
                ticket_id_val = (ticket_id.strip() if ticket_id else None) or csv_fallback_ticket
                existing = IOC.query.filter(IOC.type == ioc_type, func.lower(IOC.value) == value.lower()).first()
                if existing:
                    was_active_before = ioc_row_is_active(existing)
                    rare = _compute_rare_find_fields(ioc_type, value)
                    apply_ioc_submission_to_existing_row(
                        existing,
                        ioc_type,
                        value,
                        username,
                        'csv',
                        ticket_id=ticket_id_val,
                        comment=comment,
                        expiration_date=exp_date,
                        campaign_id=campaign_id,
                        user_id=current_user.id if current_user.is_authenticated else None,
                        tags=tags_json if tags_list else None,
                        rare=rare,
                    )
                    updated_count += 1
                    if not was_active_before:
                        _log_ioc_reactivation_history_if_needed(
                            _log_ioc_history,
                            was_active_before,
                            ioc_type,
                            value,
                            username,
                            exp_date,
                            current_user.username if current_user.is_authenticated else '',
                            comment=comment,
                            ticket_id=ticket_id_val,
                            campaign_name=campaign_name,
                            tags_list=tags_list,
                        )
                        _log_sanity_warning_history(
                            _log_ioc_history, ioc_type, value, get_sanity_warnings(value, ioc_type)
                        )
                else:
                    rare = _compute_rare_find_fields(ioc_type, value)
                    db.session.add(_create_ioc(
                        ioc_type, value, username, 'csv',
                        ticket_id=ticket_id_val, comment=comment,
                        expiration_date=exp_date, campaign_id=campaign_id,
                        user_id=current_user.id if current_user.is_authenticated else None,
                        rare=rare,
                        tags=tags_json,
                    ))
                    payload_hist = _ioc_created_history_payload(
                        entered_by=current_user.username or '',
                        assigned_to=username,
                        comment=comment,
                        ticket_id=ticket_id_val,
                        expiration_date=exp_date,
                        campaign_name=campaign_name,
                        tags_list=tags_list,
                    )
                    _log_ioc_history(ioc_type, value, 'created', username, payload_hist)
                    _log_sanity_warning_history(_log_ioc_history, ioc_type, value, get_sanity_warnings(value, ioc_type))
                    new_count += 1
                    new_iocs_for_push.append(ioc_context_from_submission(
                        ioc_type=ioc_type,
                        value=value,
                        analyst=username,
                        ticket_id=ticket_id_val,
                        comment=comment,
                        expiration_date=exp_date,
                        campaign_id=campaign_id,
                        tags_json=tags_json,
                        submission_method='csv',
                        user_id=current_user.id if current_user.is_authenticated else None,
                    ))
            summary[ioc_type] = {'updated': updated_count, 'new': new_count}
            total_updated += updated_count
            total_new += new_count

        try:
            _commit_with_retry()
        except Exception:
            db.session.rollback()
            raise

        # DXL: push all hashes from this batch to TIE if enabled
        try:
            _get_setting = _from_app('_get_setting')[0]
            if _get_setting('dxl_enabled', 'false').lower() == 'true':
                config_path = _get_setting('dxl_config_path', '').strip()
                if config_path:
                    from utils.dxl_tie import push_hash_to_tie
                    audit_log_fn = _from_app('audit_log')[0]
                    for hash_value in (findings.get('Hash') or {}):
                        push_hash_to_tie(config_path, hash_value, audit_log_fn)
        except Exception as dxl_err:
            logging.warning('DXL push after bulk_csv failed: %s', dxl_err)

        try:
            _schedule_ioc_push_batch(new_iocs_for_push)
        except Exception as ioc_push_err:
            logging.warning('IOC push after bulk_csv failed: %s', ioc_push_err)
        try:
            _schedule_esa_batch(new_iocs_for_push)
        except Exception as esa_err:
            logging.warning('ESA dictionary after bulk_csv failed: %s', esa_err)

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
        refresh_champ_score_for_user = _from_app('refresh_champ_score_for_user')[0]
        refresh_champ_score_for_user(current_user.id)
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
    Accepts: file, ttl, comment, optional ticket_id, optional assign_to (analyst username; empty = submitter).
    For each IOC: existing_permanent=True only if an active IOC exists (not revoked, not expired).
    Per-cell: one IOC candidate per CSV cell (whole cell); Paste mode still mines inside text.
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir, _get_setting,
        ioc_row_is_active,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir', '_get_setting',
        'ioc_row_is_active',
    )
    try:
        sanity_mode = _get_setting('sanity_check_mode', 'block_non_admin')
        is_admin = getattr(current_user, 'is_admin', False)
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        assign_to = (request.form.get('assign_to') or '').strip()
        username = assign_to.lower() if assign_to else current_user.username.lower()
        ttl = request.form.get('ttl', 'Permanent')
        comment = request.form.get('comment', '').strip()
        ticket_id_fallback = request.form.get('ticket_id', '').strip() or _auto_ticket_id(current_user.id)

        if ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(ttl)
            expiration_display = _format_expiration_display(exp_dt)

        stream = io.StringIO(decode_uploaded_text_bytes(file.read()))
        csv_reader = csv.reader(stream)
        all_rows = list(csv_reader)
        if not all_rows:
            return jsonify({'success': True, 'items': [], 'count': 0})

        # Do not always treat line 1 as a header: headerless IOC lists would drop the first value.
        ticket_id_column_index = None
        if _csv_first_row_is_data_not_header(all_rows[0]):
            data_rows = all_rows
        else:
            header_row = all_rows[0]
            data_rows = all_rows[1:]
            ticket_id_keywords = ['reportid', 'ticket_id', 'ref', 'reference']
            for idx, col_name in enumerate(header_row):
                if col_name.lower().strip() in ticket_id_keywords:
                    ticket_id_column_index = idx
                    break

        # Collect unique IOCs per (type, value), ticket_id from last occurrence (same as bulk_csv)
        ioc_to_ticket = {
            'IP': {}, 'Domain': {}, 'Hash': {}, 'Email': {}, 'URL': {}
        }
        for row in data_rows:
            ticket_id = None
            if ticket_id_column_index is not None and ticket_id_column_index < len(row):
                ticket_id = row[ticket_id_column_index].strip() or None
            if not ticket_id:
                ticket_id = ticket_id_fallback

            for cell in row:
                cell = (cell or '').replace('\ufeff', '').strip()
                if not cell:
                    continue
                for raw_value, ioc_type in _extract_iocs_from_csv_cell(cell):
                    final_value, final_type = _normalize_txt_ioc(raw_value)
                    if final_type is None:
                        final_type = ioc_type
                        final_value = raw_value
                    if not validate_ioc(final_value, final_type):
                        continue
                    is_crit, _ = check_sanity_critical(final_value, final_type, _data_dir)
                    if _sanity_should_block_else_warn(is_crit, is_admin, sanity_mode)[0]:
                        continue
                    is_blocked, _ = check_allowlist(final_value, final_type)
                    if is_blocked:
                        continue
                    if final_value not in ioc_to_ticket[final_type]:
                        ioc_to_ticket[final_type][final_value] = ticket_id

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
                    existing_permanent = ioc_row_is_active(existing_row)
                    existing_analyst = (existing_row.analyst or '')
                    existing_comment = (existing_row.comment or '')

                ticket_id_val = (ticket_id.strip() if ticket_id else None) or ticket_id_fallback
                items.append({
                    'ioc': value,
                    'type': ioc_type,
                    'ticket_id': ticket_id_val or '',
                    'analyst': username,
                    'date': _utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                    'comment': sanitize_comment(comment) or '',
                    'expiration': expiration_display,
                    'existing_permanent': existing_permanent,
                    'existing_analyst': existing_analyst,
                    'existing_comment': existing_comment,
                    'sanity_check': _preview_staging_sanity_summary(
                        value, ioc_type, is_admin=is_admin, sanity_mode=sanity_mode, data_dir=_data_dir
                    ),
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
    One IOC per IOC line prefix (before #): the whole token is classified, not mined for inner domains/URLs.
    Deduplicates by (ioc_type, value) case-insensitively: first occurrence order, last line wins metadata.
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir, _get_setting,
        ioc_row_is_active,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir', '_get_setting',
        'ioc_row_is_active',
    )
    try:
        sanity_mode = _get_setting('sanity_check_mode', 'block_non_admin')
        is_admin = getattr(current_user, 'is_admin', False)
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        assign_to = (request.form.get('assign_to') or '').strip()
        default_analyst = assign_to.lower() if assign_to else current_user.username.lower()
        default_ticket = request.form.get('default_ticket', '').strip() or _auto_ticket_id(current_user.id)
        default_ttl = request.form.get('default_ttl', 'Permanent')
        default_comment = request.form.get('default_comment', '').strip()

        if default_ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(default_ttl)
            expiration_display = _format_expiration_display(exp_dt)

        content = decode_uploaded_text_bytes(file.read())
        lines = content.split('\n')
        # Unique (type, value): preserve first-seen order; last line wins for ticket/comment/analyst/date
        _by_key = {}
        _key_order = []

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
            fragment = ((expanded if expanded else ioc_raw) or '').strip()
            extracted = _extract_atomic_ioc_candidates(fragment)
            parsed = _parse_txt_metadata(metadata_raw)
            analyst = (parsed['analyst'] or default_analyst).lower()
            ticket_id = parsed['ticket_id'] or default_ticket
            created_at = parsed['created_at'] or _utcnow()
            comment = sanitize_comment(parsed['comment'] or default_comment or '') or ''

            if not extracted:
                ioc_cleaned, _ = refanger(fragment)
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
                is_crit, _ = check_sanity_critical(ioc_cleaned, ioc_type, _data_dir)
                if _sanity_should_block_else_warn(is_crit, is_admin, sanity_mode)[0]:
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
                    existing_permanent = ioc_row_is_active(existing_row)
                    existing_analyst = (existing_row.analyst or '')
                    existing_comment = (existing_row.comment or '')

                dk = _preview_staging_dedup_key(ioc_type, ioc_cleaned)
                if dk not in _by_key:
                    _key_order.append(dk)
                _by_key[dk] = {
                    'ioc': ioc_cleaned,
                    'type': ioc_type,
                    'ticket_id': ticket_id or '',
                    'analyst': analyst,
                    'date': _staging_date_display(created_at),
                    'comment': comment,
                    'expiration': expiration_display,
                    'existing_permanent': existing_permanent,
                    'existing_analyst': existing_analyst,
                    'existing_comment': existing_comment,
                    'sanity_check': _preview_staging_sanity_summary(
                        ioc_cleaned, ioc_type, is_admin=is_admin, sanity_mode=sanity_mode, data_dir=_data_dir
                    ),
                }

        items = [_by_key[k] for k in _key_order]
        return jsonify({'success': True, 'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/preview-paste', methods=['POST'])
@login_required
def preview_paste():
    """
    Extract IOCs from pasted text (IPs, domains, URLs, emails, hashes).
    JSON body: { text, default_ticket?, default_ttl?, default_comment?, assign_to? }.
    Returns same format as preview_txt for staging table.
    Aggressive extraction: multiple IOCs per blob (including inside URLs) — unlike TXT/CSV file modes.
    Deduplicates by (ioc_type, value) after normalize/refang (last match wins if types collide).
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir, _get_setting,
        ioc_row_is_active,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir', '_get_setting',
        'ioc_row_is_active',
    )
    try:
        sanity_mode = _get_setting('sanity_check_mode', 'block_non_admin')
        is_admin = getattr(current_user, 'is_admin', False)
        data = request.get_json() or {}
        text = (data.get('text') or '').strip()
        if not text:
            return jsonify({'success': False, 'message': 'No text provided'}), 400
        assign_to = (data.get('assign_to') or '').strip()
        default_analyst = assign_to.lower() if assign_to else current_user.username.lower()
        default_ticket = (data.get('default_ticket') or '').strip() or _auto_ticket_id(current_user.id)
        default_ttl = (data.get('default_ttl') or 'Permanent').strip()
        default_comment = (data.get('default_comment') or '').strip()

        if default_ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(default_ttl)
            expiration_display = _format_expiration_display(exp_dt)

        text_expanded = prepare_text_for_ioc_extraction(text)
        extracted = _extract_iocs_from_text(text_expanded)
        _by_key = {}
        _key_order = []
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
            is_crit, _ = check_sanity_critical(ioc_cleaned, ioc_type, _data_dir)
            if _sanity_should_block_else_warn(is_crit, is_admin, sanity_mode)[0]:
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
                existing_permanent = ioc_row_is_active(existing_row)
                existing_analyst = (existing_row.analyst or '')
                existing_comment = (existing_row.comment or '')

            dk = _preview_staging_dedup_key(ioc_type, ioc_cleaned)
            if dk not in _by_key:
                _key_order.append(dk)
            _by_key[dk] = {
                'ioc': ioc_cleaned,
                'type': ioc_type,
                'ticket_id': default_ticket or '',
                'analyst': default_analyst,
                'date': _utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
                'comment': sanitize_comment(default_comment or '') or '',
                'expiration': expiration_display,
                'existing_permanent': existing_permanent,
                'existing_analyst': existing_analyst,
                'existing_comment': existing_comment,
                'sanity_check': _preview_staging_sanity_summary(
                    ioc_cleaned, ioc_type, is_admin=is_admin, sanity_mode=sanity_mode, data_dir=_data_dir
                ),
            }

        items = [_by_key[k] for k in _key_order]
        return jsonify({'success': True, 'items': items, 'count': len(items)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@bp.route('/api/preview-single', methods=['POST'])
@login_required
def preview_single():
    """
    Preview a single IOC for the Single staging table. Returns one item with existing_permanent
    when an active IOC exists (not revoked, not expired).
    JSON body: { type, value, ticket_id?, ttl?, comment? }.
    """
    (
        check_allowlist, calculate_expiration_date,
        _auto_ticket_id, _data_dir, _get_setting,
        ioc_row_is_active,
    ) = _from_app(
        'check_allowlist', 'calculate_expiration_date',
        '_auto_ticket_id', '_data_dir', '_get_setting',
        'ioc_row_is_active',
    )
    try:
        sanity_mode = _get_setting('sanity_check_mode', 'block_non_admin')
        is_admin = getattr(current_user, 'is_admin', False)
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
        is_crit, crit_msg = check_sanity_critical(value, ioc_type, _data_dir)
        should_block, should_warn = _sanity_should_block_else_warn(is_crit, is_admin, sanity_mode)
        if should_block:
            return jsonify({'success': False, 'message': f'⛔ {crit_msg}' if crit_msg else 'Critical/sanity block'}), 400
        is_blocked, al_reason = check_allowlist(value, ioc_type)
        if is_blocked:
            return jsonify({
                'success': False,
                'message': f'⛔ Allowlist: Block Prevented! {al_reason}' if al_reason else '⛔ Allowlist: Block Prevented!',
            }), 403
        warnings = []
        if should_warn and crit_msg:
            warnings.append(crit_msg)
        warnings.extend(get_sanity_warnings(value, ioc_type))
        sanity_cell = _preview_staging_sanity_summary(
            value, ioc_type, is_admin=is_admin, sanity_mode=sanity_mode, data_dir=_data_dir
        )
        ticket_id = (data.get('ticket_id') or '').strip() or _auto_ticket_id(current_user.id)
        ttl = (data.get('ttl') or 'Permanent').strip()
        comment = sanitize_comment((data.get('comment') or '').strip() or '') or ''
        tags_list = normalize_tags_from_input(data.get('tags'))
        if ttl == 'Permanent':
            expiration_display = 'Permanent'
        else:
            exp_dt = calculate_expiration_date(ttl)
            expiration_display = _format_expiration_display(exp_dt)
        assign_to = (data.get('assign_to') or data.get('analyst') or '').strip()
        username = assign_to.lower() if assign_to else current_user.username.lower()
        existing_permanent = False
        existing_analyst = ''
        existing_comment = ''
        existing_row = IOC.query.filter(
            IOC.type == ioc_type,
            func.lower(IOC.value) == value.lower()
        ).first()
        if existing_row:
            existing_permanent = ioc_row_is_active(existing_row)
            existing_analyst = (existing_row.analyst or '')
            existing_comment = (existing_row.comment or '')
        item = {
            'ioc': value,
            'type': ioc_type,
            'ticket_id': ticket_id or '',
            'analyst': username,
            'date': _utcnow().strftime('%Y-%m-%dT%H:%M:%S'),
            'comment': comment,
            'expiration': expiration_display,
            'existing_permanent': existing_permanent,
            'existing_analyst': existing_analyst,
            'existing_comment': existing_comment,
            'sanity_check': sanity_cell,
        }
        if tags_list:
            item['tags'] = tags_list
        if warnings:
            return jsonify({'success': True, 'item': item, 'warnings': warnings})
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
        apply_ioc_submission_to_existing_row,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _auto_ticket_id,
        _capture_champs_before, _detect_champs_changes,
        _data_dir, _get_setting,
        ioc_row_is_active,
    ) = _from_app(
        '_commit_with_retry', '_log_ioc_history', 'audit_log',
        'check_allowlist', 'calculate_expiration_date',
        'apply_ioc_submission_to_existing_row',
        '_create_ioc', '_compute_rare_find_fields',
        '_resolve_analyst_to_user', '_auto_ticket_id',
        '_capture_champs_before', '_detect_champs_changes',
        '_data_dir', '_get_setting',
        'ioc_row_is_active',
    )
    try:
        sanity_mode = _get_setting('sanity_check_mode', 'block_non_admin')
        is_admin = getattr(current_user, 'is_admin', False)
        data = request.get_json() or {}
        items = data.get('items') or []
        ttl = (data.get('ttl') or 'Permanent').strip()
        campaign_name = (data.get('campaign_name') or '').strip() or None
        submission_source = (data.get('source') or 'single').strip()
        tags_for_all_list = normalize_tags_from_input(
            data.get('tags') or data.get('tags_for_all')
        )
        tags_for_all_list, tags_err = _validate_tags_or_reject(tags_for_all_list, _get_setting)
        if tags_err is not None:
            return tags_err[0], tags_err[1]
        tags_json = json.dumps(tags_for_all_list) if tags_for_all_list else '[]'
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id

        try:
            champs_before = _capture_champs_before(current_user.id, current_user.username.lower())
        except Exception as cap_err:
            logging.warning('submit_staging: capture champs before failed: %s', cap_err)
            champs_before = {'scoring_method': '1', 'badges': set(), 'level': 0, 'rank': 0, 'score': 0}
        fallback_ticket = _auto_ticket_id(current_user.id)
        misp_sync_user = (_get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip().lower()
        from utils.ioc_push import ioc_context_from_submission
        summary = {}
        total_updated = 0
        total_new = 0
        new_hashes_for_dxl = []
        new_iocs_for_misp = []
        new_iocs_for_push = []
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
            if _sanity_should_block_else_warn(is_critical, is_admin, sanity_mode)[0]:
                continue
            is_blocked, _ = check_allowlist(ioc_value, ioc_type)
            if is_blocked:
                continue
            analyst_raw = (raw.get('analyst') or '').strip() or 'unknown'
            resolved_user = _resolve_analyst_to_user(analyst_raw)
            if resolved_user:
                _assigned_id, analyst = resolved_user
            else:
                analyst = current_user.username.lower()
            # Always store submitter as user_id (for history/audit); analyst = who gets Champs credit
            user_id = current_user.id
            ticket_id = (raw.get('ticket_id') or '').strip() or fallback_ticket
            comment = sanitize_comment(raw.get('comment') or '') or None
            date_str = (raw.get('date') or '').strip()
            server_now = _utcnow()
            created_at = _parse_date_from_staging(date_str) or server_now
            if not hasattr(created_at, 'strftime'):
                created_at = server_now
            if created_at > server_now:
                created_at = server_now
            # Per-item tags override "tags for all"
            item_tags_raw = raw.get('tags')
            if isinstance(item_tags_raw, list) and item_tags_raw:
                item_tags_list = normalize_tags_from_input(item_tags_raw)
            elif isinstance(item_tags_raw, str) and item_tags_raw.strip():
                item_tags_list = normalize_tags_from_input(item_tags_raw)
            else:
                item_tags_list = list(tags_for_all_list)
            item_tags_list, tags_err = _validate_tags_or_reject(item_tags_list, _get_setting)
            if tags_err is not None:
                db.session.rollback()
                return tags_err[0], tags_err[1]
            item_tags_json = json.dumps(item_tags_list) if item_tags_list else '[]'

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
                was_active_before = ioc_row_is_active(existing)
                rare = _compute_rare_find_fields(ioc_type, ioc_value)
                apply_ioc_submission_to_existing_row(
                    existing,
                    ioc_type,
                    ioc_value,
                    analyst,
                    submission_source,
                    ticket_id=ticket_id,
                    comment=comment,
                    expiration_date=exp_date,
                    campaign_id=campaign_id,
                    user_id=user_id,
                    tags=item_tags_json,
                    rare=rare,
                )
                total_updated += 1
                summary[ioc_type] = summary.get(ioc_type, {'updated': 0, 'new': 0})
                summary[ioc_type]['updated'] += 1
                if not was_active_before:
                    _log_ioc_reactivation_history_if_needed(
                        _log_ioc_history,
                        was_active_before,
                        ioc_type,
                        ioc_value,
                        analyst,
                        exp_date,
                        current_user.username if current_user.is_authenticated else '',
                        comment=comment,
                        ticket_id=ticket_id,
                        campaign_name=campaign_name,
                        tags_list=item_tags_list,
                    )
                    _log_sanity_warning_history(
                        _log_ioc_history, ioc_type, ioc_value, get_sanity_warnings(ioc_value, ioc_type)
                    )
            else:
                rare = _compute_rare_find_fields(ioc_type, ioc_value)
                db.session.add(_create_ioc(
                    ioc_type, ioc_value, analyst, submission_source,
                    ticket_id=ticket_id, comment=comment,
                    expiration_date=exp_date, created_at=created_at,
                    campaign_id=campaign_id, user_id=user_id, rare=rare,
                    tags=item_tags_json,
                ))
                payload_hist = _ioc_created_history_payload(
                    entered_by=current_user.username or '',
                    assigned_to=analyst,
                    comment=comment,
                    ticket_id=ticket_id,
                    expiration_date=exp_date,
                    campaign_name=campaign_name,
                    tags_list=item_tags_list,
                )
                _log_ioc_history(ioc_type, ioc_value, 'created', analyst, payload_hist)
                _log_sanity_warning_history(_log_ioc_history, ioc_type, ioc_value, get_sanity_warnings(ioc_value, ioc_type))
                total_new += 1
                if ioc_type == 'Hash':
                    new_hashes_for_dxl.append(ioc_value)
                # Only push to MISP if analyst is not the MISP sync user (avoid loop: MISP → sync → push back)
                if analyst.lower() != misp_sync_user:
                    new_iocs_for_misp.append((ioc_type, ioc_value, comment or ''))
                    new_iocs_for_push.append(ioc_context_from_submission(
                        ioc_type=ioc_type,
                        value=ioc_value,
                        analyst=analyst,
                        ticket_id=ticket_id,
                        comment=comment,
                        expiration_date=exp_date,
                        campaign_id=campaign_id,
                        tags_json=item_tags_json,
                        submission_method=submission_source,
                        user_id=user_id,
                        created_at=created_at,
                    ))
                summary[ioc_type] = summary.get(ioc_type, {'updated': 0, 'new': 0})
                summary[ioc_type]['new'] += 1

        try:
            _commit_with_retry()
        except Exception:
            db.session.rollback()
            raise

        # MISP push: send new IOCs to MISP when enabled (SOC uses ZIoCHub but feeds MISP)
        try:
            _get_setting = _from_app('_get_setting')[0]
            if _get_setting('misp_push_enabled', 'false').lower() == 'true' and new_iocs_for_misp:
                url = _get_setting('misp_url', '').strip()
                api_key = _get_setting('misp_api_key', '').strip()
                if url and api_key:
                    verify_ssl = _get_setting('misp_verify_ssl', 'false').lower() == 'true'
                    include_comment = _get_setting('misp_push_include_comment', 'true').lower() == 'true'
                    event_id_str = _get_setting('misp_push_default_event_id', '').strip()
                    event_id = int(event_id_str) if event_id_str.isdigit() else None
                    from utils.misp_push import push_ioc_to_misp
                    for ioc_type, ioc_value, comment in new_iocs_for_misp:
                        ok, msg = push_ioc_to_misp(
                            ioc_type, ioc_value, comment or None,
                            event_id=event_id, url=url, api_key=api_key, verify_ssl=verify_ssl,
                            include_comment=include_comment,
                        )
                        if not ok:
                            logging.warning('MISP push after staging failed for %s %s: %s', ioc_type, ioc_value[:50], msg)
                        elif event_id is None:
                            event_id = int(msg.split()[-1]) if msg.split()[-1].isdigit() else event_id
        except Exception as misp_err:
            logging.warning('MISP push after submit_staging failed: %s', misp_err)

        try:
            _schedule_ioc_push_batch(new_iocs_for_push)
        except Exception as ioc_push_err:
            logging.warning('IOC push after submit_staging failed: %s', ioc_push_err)
        try:
            _schedule_esa_batch(new_iocs_for_push)
        except Exception as esa_err:
            logging.warning('ESA dictionary after submit_staging failed: %s', esa_err)

        # DXL: push new hashes to TIE if enabled
        try:
            _get_setting = _from_app('_get_setting')[0]
            if _get_setting('dxl_enabled', 'false').lower() == 'true' and new_hashes_for_dxl:
                config_path = _get_setting('dxl_config_path', '').strip()
                if config_path:
                    from utils.dxl_tie import push_hash_to_tie
                    for hash_value in new_hashes_for_dxl:
                        push_hash_to_tie(config_path, hash_value, audit_log)
        except Exception as dxl_err:
            logging.warning('DXL push after submit_staging failed: %s', dxl_err)

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
        try:
            refresh_champ_score_for_user = _from_app('refresh_champ_score_for_user')[0]
            refresh_champ_score_for_user(current_user.id)
        except Exception as refresh_err:
            logging.warning('submit_staging: refresh_champ_score failed (data saved): %s', refresh_err)
        resp = {'success': True, 'message': message, 'summary': summary, 'total': total_new + total_updated}
        if total_new > 0:
            try:
                resp.update(_detect_champs_changes(champs_before, current_user.id, current_user.username.lower()))
            except Exception as champs_err:
                logging.warning('submit_staging: champs change detection failed (data saved): %s', champs_err)
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
        apply_ioc_submission_to_existing_row,
        _create_ioc, _compute_rare_find_fields,
        _resolve_analyst_to_user, _auto_ticket_id,
        _capture_champs_before, _detect_champs_changes,
        ioc_row_is_active,
    ) = _from_app(
        '_commit_with_retry', 'audit_log', '_log_ioc_history',
        'check_allowlist', 'calculate_expiration_date',
        'apply_ioc_submission_to_existing_row',
        '_create_ioc', '_compute_rare_find_fields',
        '_resolve_analyst_to_user', '_auto_ticket_id',
        '_capture_champs_before', '_detect_champs_changes',
        'ioc_row_is_active',
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
        tags_list = normalize_tags_from_input(
            request.form.get('tags') or request.form.get('tags_for_all') or ''
        )
        _get_setting = _from_app('_get_setting')[0]
        tags_list, tags_err = _validate_tags_or_reject(tags_list, _get_setting)
        if tags_err is not None:
            return tags_err[0], tags_err[1]
        tags_json = json.dumps(tags_list) if tags_list else '[]'
        campaign_id = None
        if campaign_name:
            c = Campaign.query.filter_by(name=campaign_name).first()
            if c:
                campaign_id = c.id
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        text = decode_uploaded_text_bytes(file.read())
        exp_date = calculate_expiration_date(ttl)
        findings = {'IP': {}, 'Domain': {}, 'Hash': {}, 'Email': {}, 'URL': {}}
        from utils.ioc_push import ioc_context_from_submission
        new_iocs_for_push = []

        for raw_line in text.splitlines():
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
            final_date = parsed['created_at'] or _utcnow()
            final_ticket_id = parsed['ticket_id'] or default_ticket_id
            comment_sanitized = sanitize_comment(parsed['comment'] or '')

            expanded = prepare_text_for_ioc_extraction(ioc_raw)
            fragment = ((expanded if expanded else ioc_raw) or '').strip()
            extracted = _extract_atomic_ioc_candidates(fragment)
            if not extracted:
                ioc_cleaned, _ = refanger(fragment)
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
                        'analyst_raw': (parsed['analyst'] or '').strip().lower() or None,
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
                    was_active_before = ioc_row_is_active(existing)
                    u = meta['user']
                    analyst_from_file = meta.get('analyst_raw')
                    resolved_bulk_txt = _resolve_analyst_to_user(u)
                    if resolved_bulk_txt:
                        store_user_id, store_analyst = resolved_bulk_txt
                    else:
                        store_analyst = (analyst_from_file or current_user.username or '').strip().lower() or current_user.username.lower()
                        store_user_id = current_user.id if current_user.is_authenticated else None
                    rare = _compute_rare_find_fields(ioc_type, value)
                    apply_ioc_submission_to_existing_row(
                        existing,
                        ioc_type,
                        value,
                        store_analyst,
                        'txt',
                        ticket_id=meta['ticket_id'],
                        comment=meta['comment'],
                        expiration_date=exp_date,
                        campaign_id=campaign_id,
                        user_id=store_user_id,
                        tags=tags_json if tags_list else None,
                        rare=rare,
                    )
                    updated_count += 1
                    if not was_active_before:
                        _log_ioc_reactivation_history_if_needed(
                            _log_ioc_history,
                            was_active_before,
                            ioc_type,
                            value,
                            store_analyst,
                            exp_date,
                            current_user.username if current_user.is_authenticated else '',
                            comment=meta.get('comment'),
                            ticket_id=meta.get('ticket_id'),
                            campaign_name=campaign_name,
                            tags_list=tags_list,
                        )
                else:
                    rare = _compute_rare_find_fields(ioc_type, value)
                    u = meta['user']
                    analyst_from_file = meta.get('analyst_raw')
                    resolved_bulk_txt = _resolve_analyst_to_user(u)
                    if resolved_bulk_txt:
                        store_user_id, store_analyst = resolved_bulk_txt
                    else:
                        # Use analyst name from file so points go to them (not to uploader) even if not in users table
                        store_analyst = (analyst_from_file or current_user.username or '').strip().lower() or current_user.username.lower()
                        store_user_id = current_user.id if current_user.is_authenticated else None
                    db.session.add(_create_ioc(
                        ioc_type, value, store_analyst, 'txt',
                        ticket_id=meta['ticket_id'], comment=meta['comment'],
                        expiration_date=exp_date, created_at=meta['created_at'],
                        campaign_id=campaign_id, user_id=store_user_id,
                        rare=rare,
                        tags=tags_json,
                    ))
                    payload_hist = _ioc_created_history_payload(
                        entered_by=current_user.username or '',
                        assigned_to=store_analyst,
                        comment=meta.get('comment'),
                        ticket_id=meta.get('ticket_id'),
                        expiration_date=exp_date,
                        campaign_name=campaign_name,
                        tags_list=tags_list,
                    )
                    _log_ioc_history(ioc_type, value, 'created', store_analyst, payload_hist)
                    new_count += 1
                    new_iocs_for_push.append(ioc_context_from_submission(
                        ioc_type=ioc_type,
                        value=value,
                        analyst=store_analyst,
                        ticket_id=meta['ticket_id'],
                        comment=meta['comment'],
                        expiration_date=exp_date,
                        campaign_id=campaign_id,
                        tags_json=tags_json,
                        submission_method='txt',
                        user_id=store_user_id,
                        created_at=meta['created_at'],
                    ))
            summary[ioc_type] = {'updated': updated_count, 'new': new_count}
            total_updated += updated_count
            total_new += new_count

        try:
            _commit_with_retry()
        except Exception:
            db.session.rollback()
            raise

        # DXL: push all hashes from this batch to TIE if enabled
        try:
            _get_setting = _from_app('_get_setting')[0]
            if _get_setting('dxl_enabled', 'false').lower() == 'true':
                config_path = _get_setting('dxl_config_path', '').strip()
                if config_path:
                    from utils.dxl_tie import push_hash_to_tie
                    audit_log_fn = _from_app('audit_log')[0]
                    for hash_value in (findings.get('Hash') or {}):
                        push_hash_to_tie(config_path, hash_value, audit_log_fn)
        except Exception as dxl_err:
            logging.warning('DXL push after upload_txt failed: %s', dxl_err)

        try:
            _schedule_ioc_push_batch(new_iocs_for_push)
        except Exception as ioc_push_err:
            logging.warning('IOC push after upload_txt failed: %s', ioc_push_err)
        try:
            _schedule_esa_batch(new_iocs_for_push)
        except Exception as esa_err:
            logging.warning('ESA dictionary after upload_txt failed: %s', esa_err)

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
        refresh_champ_score_for_user = _from_app('refresh_champ_score_for_user')[0]
        refresh_champ_score_for_user(current_user.id)
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
