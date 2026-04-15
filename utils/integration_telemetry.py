"""
Last-seen telemetry: /feed and /taxii2 pulls (per client IP + path), API IOC ingest, YARA upload, DXL TIE push.
Used by Feed Pulse → Connections (no Linux log access required).
"""
import json
import logging
import re
import threading
from collections import defaultdict
import time
from datetime import datetime
from urllib.parse import urlparse

from flask import has_request_context, request

from extensions import db
from models import FeedSourceLastSeen, SystemSetting, _utcnow

logger = logging.getLogger(__name__)

_THROTTLE_SEC = 60.0
_THROTTLE_PRUNE_SEC = 300.0
_feed_throttle_lock = threading.Lock()
_feed_throttle = {}  # (ip, path) -> monotonic time of last DB write

KEY_API_IOC = 'telemetry_last_api_ioc_ingest_at'
KEY_API_YARA = 'telemetry_last_api_yara_upload_at'
KEY_DXL = 'telemetry_last_dxl_tie_push_at'
KEY_IOC_PUSH_ATTEMPT = 'telemetry_last_ioc_push_attempt_at'
KEY_IOC_PUSH_OK = 'telemetry_last_ioc_push_success_at'
KEY_IOC_PUSH_FAIL = 'telemetry_last_ioc_push_failure_at'
KEY_IOC_PUSH_RESULTS = 'telemetry_last_ioc_push_results_json'
KEY_IOC_PUSH_CONTEXT = 'telemetry_last_ioc_push_context_json'

KEY_IOC_EXPIRE_PUSH_ATTEMPT = 'telemetry_last_ioc_expire_push_attempt_at'
KEY_IOC_EXPIRE_PUSH_OK = 'telemetry_last_ioc_expire_push_success_at'
KEY_IOC_EXPIRE_PUSH_FAIL = 'telemetry_last_ioc_expire_push_failure_at'
KEY_IOC_EXPIRE_PUSH_RESULTS = 'telemetry_last_ioc_expire_push_results_json'
KEY_IOC_EXPIRE_PUSH_CONTEXT = 'telemetry_last_ioc_expire_push_context_json'

KEY_IOC_MANUAL_REMOVE_PUSH_ATTEMPT = 'telemetry_last_ioc_manual_remove_push_attempt_at'
KEY_IOC_MANUAL_REMOVE_PUSH_OK = 'telemetry_last_ioc_manual_remove_push_success_at'
KEY_IOC_MANUAL_REMOVE_PUSH_FAIL = 'telemetry_last_ioc_manual_remove_push_failure_at'
KEY_IOC_MANUAL_REMOVE_PUSH_RESULTS = 'telemetry_last_ioc_manual_remove_push_results_json'
KEY_IOC_MANUAL_REMOVE_PUSH_CONTEXT = 'telemetry_last_ioc_manual_remove_push_context_json'

# YARA automation (Settings → YARA push targets): POST on approve, DELETE on rule delete
KEY_YARA_AUTOMATION_PUSH_ATTEMPT = 'telemetry_last_yara_automation_push_attempt_at'
KEY_YARA_AUTOMATION_PUSH_OK = 'telemetry_last_yara_automation_push_success_at'
KEY_YARA_AUTOMATION_PUSH_FAIL = 'telemetry_last_yara_automation_push_failure_at'
KEY_YARA_AUTOMATION_PUSH_RESULTS = 'telemetry_last_yara_automation_push_results_json'
KEY_YARA_AUTOMATION_PUSH_CONTEXT = 'telemetry_last_yara_automation_push_context_json'

KEY_YARA_AUTOMATION_DELETE_ATTEMPT = 'telemetry_last_yara_automation_delete_attempt_at'
KEY_YARA_AUTOMATION_DELETE_OK = 'telemetry_last_yara_automation_delete_success_at'
KEY_YARA_AUTOMATION_DELETE_FAIL = 'telemetry_last_yara_automation_delete_failure_at'
KEY_YARA_AUTOMATION_DELETE_RESULTS = 'telemetry_last_yara_automation_delete_results_json'
KEY_YARA_AUTOMATION_DELETE_CONTEXT = 'telemetry_last_yara_automation_delete_context_json'

# Successful HTTP 200 pulls on these URL prefixes are recorded (throttled per IP + path).
_TELEMETRY_PULL_PREFIXES = ('/feed', '/taxii2')


def _client_ip():
    if not has_request_context():
        return ''
    xff = (request.headers.get('X-Forwarded-For') or '').strip()
    if xff:
        return xff.split(',')[0].strip()[:45]
    return (request.remote_addr or '')[:45] or 'unknown'


def record_feed_pull_if_ok(response):
    """Record successful public pull response (200) for /feed or /taxii2. Throttled per (IP, path).

    Call from feeds and taxii2 blueprint after_request handlers.
    """
    if not has_request_context():
        return
    try:
        if response is None or getattr(response, 'status_code', None) != 200:
            return
        path = request.path or ''
        if not any(path.startswith(p) for p in _TELEMETRY_PULL_PREFIXES):
            return
        path = path[:512]
        ip = _client_ip() or 'unknown'
        now = time.monotonic()
        key = (ip, path)
        with _feed_throttle_lock:
            cutoff = now - _THROTTLE_PRUNE_SEC
            dead = [k for k, v in _feed_throttle.items() if v < cutoff]
            for k in dead:
                del _feed_throttle[k]
            last = _feed_throttle.get(key, 0)
            if now - last < _THROTTLE_SEC:
                return
            _feed_throttle[key] = now
        ts = _utcnow()
        row = FeedSourceLastSeen.query.filter_by(client_ip=ip, feed_path=path).first()
        if row:
            row.last_seen_at = ts
        else:
            db.session.add(FeedSourceLastSeen(client_ip=ip, feed_path=path, last_seen_at=ts))
        db.session.commit()
    except Exception:
        logger.debug('record_feed_pull_if_ok failed', exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def _set_setting_ts(key: str):
    try:
        s = SystemSetting.query.filter_by(key=key).first()
        val = _utcnow().isoformat()
        if s:
            s.value = val
        else:
            db.session.add(SystemSetting(key=key, value=val))
        db.session.commit()
    except Exception:
        logger.debug('telemetry _set_setting_ts %s failed', key, exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def record_api_ioc_ingest():
    _set_setting_ts(KEY_API_IOC)


def record_api_yara_upload():
    _set_setting_ts(KEY_API_YARA)


def record_dxl_tie_push():
    _set_setting_ts(KEY_DXL)


def record_yara_automation_results(results: dict, *, kind: str = 'push', context: dict | None = None) -> None:
    """
    Store last YARA automation attempt (POST after approve, or DELETE after rule removal) for Feed Pulse → Connections.
    Expected shape: { overall_success: bool, results: [ { name, url, success, message } ] }
    kind: 'push' | 'delete'
    """
    import json
    try:
        now = _utcnow().isoformat()
        kind_l = (kind or '').strip().lower()
        if kind_l in ('delete', 'remove', 'deletion'):
            k_attempt, k_ok, k_fail, k_results, k_ctx = (
                KEY_YARA_AUTOMATION_DELETE_ATTEMPT,
                KEY_YARA_AUTOMATION_DELETE_OK,
                KEY_YARA_AUTOMATION_DELETE_FAIL,
                KEY_YARA_AUTOMATION_DELETE_RESULTS,
                KEY_YARA_AUTOMATION_DELETE_CONTEXT,
            )
        else:
            k_attempt, k_ok, k_fail, k_results, k_ctx = (
                KEY_YARA_AUTOMATION_PUSH_ATTEMPT,
                KEY_YARA_AUTOMATION_PUSH_OK,
                KEY_YARA_AUTOMATION_PUSH_FAIL,
                KEY_YARA_AUTOMATION_PUSH_RESULTS,
                KEY_YARA_AUTOMATION_PUSH_CONTEXT,
            )

        s_attempt = SystemSetting.query.filter_by(key=k_attempt).first()
        if s_attempt:
            s_attempt.value = now
        else:
            db.session.add(SystemSetting(key=k_attempt, value=now))

        ok = bool(results.get('overall_success')) if isinstance(results, dict) else False
        key_status = k_ok if ok else k_fail
        s_status = SystemSetting.query.filter_by(key=key_status).first()
        if s_status:
            s_status.value = now
        else:
            db.session.add(SystemSetting(key=key_status, value=now))

        payload = results if isinstance(results, dict) else {'overall_success': False, 'results': []}
        try:
            payload_s = json.dumps(payload, ensure_ascii=False)[:200000]
        except Exception:
            payload_s = json.dumps({'overall_success': ok, 'results': []})
        s_res = SystemSetting.query.filter_by(key=k_results).first()
        if s_res:
            s_res.value = payload_s
        else:
            db.session.add(SystemSetting(key=k_results, value=payload_s))

        if isinstance(context, dict) and context:
            try:
                ctx_s = json.dumps(context, ensure_ascii=False)[:50000]
                s_ctx = SystemSetting.query.filter_by(key=k_ctx).first()
                if s_ctx:
                    s_ctx.value = ctx_s
                else:
                    db.session.add(SystemSetting(key=k_ctx, value=ctx_s))
            except Exception:
                pass

        db.session.commit()
    except Exception:
        logger.debug('record_yara_automation_results failed', exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def record_ioc_push_results(results: dict, *, kind: str = 'create', context: dict | None = None) -> None:
    """
    Store last IOC push attempt summary (per-target results) for Feed Pulse → Connections.
    Expected shape: { overall_success: bool, results: [ {name,url,success,message} ] }
    """
    import json
    try:
        now = _utcnow().isoformat()
        kind_l = (kind or '').strip().lower()
        if kind_l in ('expire', 'expired', 'expire_remove'):
            k_attempt, k_ok, k_fail, k_results, k_ctx = (
                KEY_IOC_EXPIRE_PUSH_ATTEMPT, KEY_IOC_EXPIRE_PUSH_OK, KEY_IOC_EXPIRE_PUSH_FAIL, KEY_IOC_EXPIRE_PUSH_RESULTS, KEY_IOC_EXPIRE_PUSH_CONTEXT
            )
        elif kind_l in ('manual_remove', 'manual', 'delete_remove', 'manual_delete'):
            k_attempt, k_ok, k_fail, k_results, k_ctx = (
                KEY_IOC_MANUAL_REMOVE_PUSH_ATTEMPT, KEY_IOC_MANUAL_REMOVE_PUSH_OK, KEY_IOC_MANUAL_REMOVE_PUSH_FAIL, KEY_IOC_MANUAL_REMOVE_PUSH_RESULTS, KEY_IOC_MANUAL_REMOVE_PUSH_CONTEXT
            )
        else:
            k_attempt, k_ok, k_fail, k_results, k_ctx = (
                KEY_IOC_PUSH_ATTEMPT, KEY_IOC_PUSH_OK, KEY_IOC_PUSH_FAIL, KEY_IOC_PUSH_RESULTS, KEY_IOC_PUSH_CONTEXT
            )

        s_attempt = SystemSetting.query.filter_by(key=k_attempt).first()
        if s_attempt:
            s_attempt.value = now
        else:
            db.session.add(SystemSetting(key=k_attempt, value=now))

        ok = bool(results.get('overall_success')) if isinstance(results, dict) else False
        key_status = k_ok if ok else k_fail
        s_status = SystemSetting.query.filter_by(key=key_status).first()
        if s_status:
            s_status.value = now
        else:
            db.session.add(SystemSetting(key=key_status, value=now))

        # Keep details for UI
        payload = results if isinstance(results, dict) else {'overall_success': False, 'results': []}
        try:
            payload_s = json.dumps(payload, ensure_ascii=False)[:200000]
        except Exception:
            payload_s = json.dumps({'overall_success': ok, 'results': []})
        s_res = SystemSetting.query.filter_by(key=k_results).first()
        if s_res:
            s_res.value = payload_s
        else:
            db.session.add(SystemSetting(key=k_results, value=payload_s))

        # Store context for retry (best-effort; keep small)
        if isinstance(context, dict) and context:
            try:
                ctx_s = json.dumps(context, ensure_ascii=False)[:50000]
                s_ctx = SystemSetting.query.filter_by(key=k_ctx).first()
                if s_ctx:
                    s_ctx.value = ctx_s
                else:
                    db.session.add(SystemSetting(key=k_ctx, value=ctx_s))
            except Exception:
                pass

        db.session.commit()
    except Exception:
        logger.debug('record_ioc_push_results failed', exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def _parse_iso_ts(val):
    """Parse SystemSetting ISO timestamp; return datetime or None."""
    if not val or not isinstance(val, str):
        return None
    s = val.strip()
    if not s:
        return None
    try:
        if s.endswith('Z'):
            s = s[:-1] + '+00:00'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _host_from_url(url: str) -> str:
    """Return hostname or IP from URL (for display)."""
    raw = (url or '').strip()
    if not raw:
        return ''
    if '://' not in raw:
        raw = 'https://' + raw
    try:
        p = urlparse(raw)
        h = (p.hostname or '').strip()
        return h
    except Exception:
        return ''


def _parse_push_results_json(json_str):
    if not json_str:
        return []
    try:
        p = json.loads(json_str)
        if not isinstance(p, dict):
            return []
        r = p.get('results')
        return r if isinstance(r, list) else []
    except Exception:
        return []


def _build_automation_targets(_get):
    """
    One row per unique outbound URL (or name if URL missing): admin name, host, last attempt time,
    push kinds that touched this target. last_seen is max(attempt_at) across batches where the
    target appears in stored results.
    """
    specs = (
        ('ioc_push', KEY_IOC_PUSH_ATTEMPT, KEY_IOC_PUSH_RESULTS),
        ('ioc_expire', KEY_IOC_EXPIRE_PUSH_ATTEMPT, KEY_IOC_EXPIRE_PUSH_RESULTS),
        ('ioc_manual_remove', KEY_IOC_MANUAL_REMOVE_PUSH_ATTEMPT, KEY_IOC_MANUAL_REMOVE_PUSH_RESULTS),
        ('yara_push', KEY_YARA_AUTOMATION_PUSH_ATTEMPT, KEY_YARA_AUTOMATION_PUSH_RESULTS),
        ('yara_delete', KEY_YARA_AUTOMATION_DELETE_ATTEMPT, KEY_YARA_AUTOMATION_DELETE_RESULTS),
    )
    entries = []
    for kind, attempt_key, results_key in specs:
        at_raw = _get(attempt_key)
        at_dt = _parse_iso_ts(at_raw) if at_raw else None
        if not at_dt:
            continue
        for r in _parse_push_results_json(_get(results_key)):
            if not isinstance(r, dict):
                continue
            url = (r.get('url') or '').strip()
            name = (r.get('name') or '').strip() or '—'
            name_norm = re.sub(r'\s+', ' ', name).lower()
            key = url.lower() if url else f'name:{name_norm}'
            host = _host_from_url(url)
            entries.append({
                'key': key,
                'name': name,
                'url': url,
                'host': host or (name if not url else ''),
                'at': at_dt,
                'at_iso': at_raw,
                'kind': kind,
                'success': bool(r.get('success')),
            })

    if not entries:
        return []

    key_entries = defaultdict(list)
    for e in entries:
        key_entries[e['key']].append(e)

    rows = []
    for _k, lst in key_entries.items():
        max_at = max(e['at'] for e in lst)
        same = [e for e in lst if e['at'] == max_at]
        winner = same[0]
        kinds = sorted({e['kind'] for e in same})
        if not same:
            st = 'unknown'
        elif all(e.get('success') for e in same):
            st = 'ok'
        elif any(e.get('success') for e in same):
            st = 'partial'
        else:
            st = 'fail'
        rows.append({
            'name': winner.get('name') or '—',
            'url': winner.get('url') or '',
            'host': winner.get('host') or '',
            'last_seen_at': winner.get('at_iso') or max_at.isoformat(),
            'kinds': kinds,
            'status': st,
        })

    rows.sort(key=lambda r: _parse_iso_ts(r.get('last_seen_at')) or datetime.min, reverse=True)
    return rows


def get_connections_snapshot():
    rows = (
        FeedSourceLastSeen.query
        .order_by(FeedSourceLastSeen.last_seen_at.desc())
        .limit(2000)
        .all()
    )

    def _get(key):
        s = SystemSetting.query.filter_by(key=key).first()
        v = (s.value or '').strip() if s else ''
        return v or None

    automation_targets = _build_automation_targets(_get)

    return {
        'feed_access': [
            {
                'client_ip': r.client_ip,
                'feed_path': r.feed_path,
                'last_seen_at': r.last_seen_at.isoformat() if r.last_seen_at else None,
            }
            for r in rows
        ],
        'last_api_ioc_ingest_at': _get(KEY_API_IOC),
        'last_api_yara_upload_at': _get(KEY_API_YARA),
        'last_dxl_tie_push_at': _get(KEY_DXL),
        'last_ioc_push_attempt_at': _get(KEY_IOC_PUSH_ATTEMPT),
        'last_ioc_push_success_at': _get(KEY_IOC_PUSH_OK),
        'last_ioc_push_failure_at': _get(KEY_IOC_PUSH_FAIL),
        'last_ioc_push_results_json': _get(KEY_IOC_PUSH_RESULTS),
        'last_ioc_push_context_json': _get(KEY_IOC_PUSH_CONTEXT),
        'last_ioc_expire_push_attempt_at': _get(KEY_IOC_EXPIRE_PUSH_ATTEMPT),
        'last_ioc_expire_push_success_at': _get(KEY_IOC_EXPIRE_PUSH_OK),
        'last_ioc_expire_push_failure_at': _get(KEY_IOC_EXPIRE_PUSH_FAIL),
        'last_ioc_expire_push_results_json': _get(KEY_IOC_EXPIRE_PUSH_RESULTS),
        'last_ioc_expire_push_context_json': _get(KEY_IOC_EXPIRE_PUSH_CONTEXT),
        'last_ioc_manual_remove_push_attempt_at': _get(KEY_IOC_MANUAL_REMOVE_PUSH_ATTEMPT),
        'last_ioc_manual_remove_push_success_at': _get(KEY_IOC_MANUAL_REMOVE_PUSH_OK),
        'last_ioc_manual_remove_push_failure_at': _get(KEY_IOC_MANUAL_REMOVE_PUSH_FAIL),
        'last_ioc_manual_remove_push_results_json': _get(KEY_IOC_MANUAL_REMOVE_PUSH_RESULTS),
        'last_ioc_manual_remove_push_context_json': _get(KEY_IOC_MANUAL_REMOVE_PUSH_CONTEXT),
        'last_yara_automation_push_attempt_at': _get(KEY_YARA_AUTOMATION_PUSH_ATTEMPT),
        'last_yara_automation_push_success_at': _get(KEY_YARA_AUTOMATION_PUSH_OK),
        'last_yara_automation_push_failure_at': _get(KEY_YARA_AUTOMATION_PUSH_FAIL),
        'last_yara_automation_push_results_json': _get(KEY_YARA_AUTOMATION_PUSH_RESULTS),
        'last_yara_automation_push_context_json': _get(KEY_YARA_AUTOMATION_PUSH_CONTEXT),
        'last_yara_automation_delete_attempt_at': _get(KEY_YARA_AUTOMATION_DELETE_ATTEMPT),
        'last_yara_automation_delete_success_at': _get(KEY_YARA_AUTOMATION_DELETE_OK),
        'last_yara_automation_delete_failure_at': _get(KEY_YARA_AUTOMATION_DELETE_FAIL),
        'last_yara_automation_delete_results_json': _get(KEY_YARA_AUTOMATION_DELETE_RESULTS),
        'last_yara_automation_delete_context_json': _get(KEY_YARA_AUTOMATION_DELETE_CONTEXT),
        'automation_targets': automation_targets,
    }
