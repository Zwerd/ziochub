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

# Vendor integrations (Integrations tab): last successful IOC/YARA push per platform (JSON per vendor)
KEY_VENDOR_PUSH_DETAIL_CORTEX = 'telemetry_vendor_push_detail_cortex_xdr'
KEY_VENDOR_PUSH_DETAIL_GOOGLE = 'telemetry_vendor_push_detail_google_secops'

# Vendor push attempts (last attempt, regardless of success) for Push State table
KEY_VENDOR_PUSH_ATTEMPT_CORTEX = 'telemetry_vendor_push_attempt_cortex_xdr'
KEY_VENDOR_PUSH_ATTEMPT_GOOGLE = 'telemetry_vendor_push_attempt_google_secops'


def _client_ip():
    if not has_request_context():
        return ''
    xff = (request.headers.get('X-Forwarded-For') or '').strip()
    if xff:
        return xff.split(',')[0].strip()[:45]
    return (request.remote_addr or '')[:45] or 'unknown'


def record_feed_pull_if_ok(response):
    """Record last pull attempt for /feed or /taxii2 (success/fail). Throttled per (IP, path).

    Call from feeds and taxii2 blueprint after_request handlers.
    """
    if not has_request_context():
        return
    try:
        if response is None or getattr(response, 'status_code', None) is None:
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
        status_code = int(getattr(response, 'status_code', 0) or 0)
        ok = status_code == 200
        row = FeedSourceLastSeen.query.filter_by(client_ip=ip, feed_path=path).first()
        if row:
            row.last_seen_at = ts
            row.last_status_code = status_code
            row.last_ok = ok
        else:
            db.session.add(FeedSourceLastSeen(
                client_ip=ip,
                feed_path=path,
                last_seen_at=ts,
                last_status_code=status_code,
                last_ok=ok,
            ))
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


def record_vendor_integration_push(vendor_id: str, data_kind: str) -> None:
    """
    Record last outbound push timestamp for a built-in vendor integration (Cortex XDR, Google SecOps).
    ``data_kind`` is ``IOC`` or ``YARA`` (stored as upper-case keys in a JSON object per vendor).
    """
    kind_u = (data_kind or '').strip().upper()
    if kind_u not in ('IOC', 'YARA'):
        return
    key_map = {
        'cortex_xdr': KEY_VENDOR_PUSH_DETAIL_CORTEX,
        'google_secops': KEY_VENDOR_PUSH_DETAIL_GOOGLE,
    }
    setting_key = key_map.get((vendor_id or '').strip())
    if not setting_key:
        return
    try:
        now = _utcnow().isoformat()
        s = SystemSetting.query.filter_by(key=setting_key).first()
        raw = (s.value if s else '') or '{}'
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            obj = {}
        if not isinstance(obj, dict):
            obj = {}
        obj[kind_u] = now
        val = json.dumps(obj, ensure_ascii=False)
        if s:
            s.value = val
        else:
            db.session.add(SystemSetting(key=setting_key, value=val))
        db.session.commit()
    except Exception:
        logger.debug('record_vendor_integration_push failed', exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def record_vendor_push_if_applicable(vendor_id: str, ok: bool, msg: str) -> None:
    """After Cortex/Google IOC push: record IOC timestamp only on real outbound success."""
    if not ok:
        return
    m = (msg or '')
    if m == 'disabled' or 'skip_' in m:
        return
    if vendor_id == 'google_secops' and 'skipped_incomplete_data_table_config' in m:
        return
    record_vendor_integration_push(vendor_id, 'IOC')


def record_vendor_push_attempt(vendor_id: str, *, data_kind: str = 'IOC', ok: bool, message: str = '', count: int | None = None) -> None:
    """
    Record last outbound push attempt to a built-in vendor integration (Cortex XDR, Google SecOps).
    Unlike `record_vendor_integration_push`, this stores success/failure + a short reason + optional count.
    """
    kind_u = (data_kind or '').strip().upper()
    if kind_u not in ('IOC', 'YARA'):
        kind_u = 'IOC'
    key_map = {
        'cortex_xdr': KEY_VENDOR_PUSH_ATTEMPT_CORTEX,
        'google_secops': KEY_VENDOR_PUSH_ATTEMPT_GOOGLE,
    }
    setting_key = key_map.get((vendor_id or '').strip())
    if not setting_key:
        return
    try:
        now = _utcnow().isoformat()
        payload = {
            'at': now,
            'ok': bool(ok),
            'kind': kind_u,
            'count': int(count) if isinstance(count, int) else None,
            'message': (str(message or '')[:240]),
        }
        s = SystemSetting.query.filter_by(key=setting_key).first()
        val = json.dumps(payload, ensure_ascii=False)
        if s:
            s.value = val
        else:
            db.session.add(SystemSetting(key=setting_key, value=val))
        db.session.commit()
    except Exception:
        logger.debug('record_vendor_push_attempt failed', exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def _resolve_hostname_ip(hostname: str) -> str:
    """Best-effort IPv4 (or first IP) for display next to hostname."""
    hn = (hostname or '').strip()
    if not hn:
        return ''
    try:
        import socket
        infos = socket.getaddrinfo(hn, None, type=socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip:
                ips.append(ip)
        for ip in ips:
            if ip and ':' not in ip:
                return ip
        return ips[0] if ips else ''
    except Exception:
        return ''


def _parse_vendor_push_detail_json(raw_val) -> dict[str, str]:
    if not raw_val or not isinstance(raw_val, str):
        return {}
    try:
        o = json.loads(raw_val)
        if not isinstance(o, dict):
            return {}
        out = {}
        for k, v in o.items():
            if isinstance(k, str) and k.upper() in ('IOC', 'YARA') and isinstance(v, str) and v.strip():
                out[k.upper()] = v.strip()
        return out
    except (json.JSONDecodeError, TypeError):
        return {}


def _parse_vendor_attempt_json(raw_val) -> dict:
    if not raw_val or not isinstance(raw_val, str):
        return {}
    try:
        o = json.loads(raw_val)
        return o if isinstance(o, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _vendor_attempt_setting_key(vendor_id: str) -> str | None:
    m = {
        'cortex_xdr': KEY_VENDOR_PUSH_ATTEMPT_CORTEX,
        'google_secops': KEY_VENDOR_PUSH_ATTEMPT_GOOGLE,
    }
    return m.get((vendor_id or '').strip())


def _vendor_attempt_for_kind(_get, vendor_id: str, kind_u: str) -> dict:
    """Return last attempt payload for vendor and kind (IOC/YARA), or {}."""
    k = _vendor_attempt_setting_key(vendor_id)
    if not k:
        return {}
    obj = _parse_vendor_attempt_json(_get(k) or '')
    if not obj:
        return {}
    # Stored as one payload at a time; ensure kind matches (best-effort)
    if (obj.get('kind') or '').upper() != (kind_u or '').upper():
        return {}
    return obj


def _google_secops_push_display_address(_get) -> tuple[str, str]:
    """Return (display_url_or_label, hostname) for Chronicle API."""
    raw_base = (_get('google_secops_chronicle_api_base') or '').strip().rstrip('/')
    loc = (_get('google_secops_location') or '').strip()
    if raw_base:
        host = _host_from_url(raw_base)
        return raw_base, host
    if loc:
        derived = f'https://{loc}-chronicle.googleapis.com'
        return derived, f'{loc}-chronicle.googleapis.com'
    return '', ''


def _google_secops_is_configured(_get) -> bool:
    proj = (_get('google_secops_project_number') or '').strip()
    loc = (_get('google_secops_location') or '').strip()
    inst = (_get('google_secops_instance_id') or '').strip() or (_get('google_secops_customer_id') or '').strip()
    tid = (_get('google_secops_data_table_id') or '').strip()
    creds = (_get('google_secops_credentials_json') or '').strip()
    base_ok = bool((_get('google_secops_chronicle_api_base') or '').strip() or loc)
    return bool(proj and loc and inst and tid and creds and base_ok)


def _build_integration_push_state_entries(_get):
    """
    Outbound vendor integrations (Admin → Integrations): Cortex XDR, Google SecOps.
    One flat row per (system, data kind) with last push time (IOC/YARA tracked separately in JSON).
    """
    rows = []

    cx_url = (_get('cortex_xdr_base_url') or '').strip()
    cx_name = (_get('cortex_xdr_display_name') or '').strip() or 'Cortex XDR'
    if cx_url:
        detail = _parse_vendor_push_detail_json(_get(KEY_VENDOR_PUSH_DETAIL_CORTEX) or '')
        host = _host_from_url(cx_url)
        hip = _resolve_hostname_ip(host)
        for kind in ('IOC', 'YARA'):
            attempt = _vendor_attempt_for_kind(_get, 'cortex_xdr', kind)
            rows.append({
                'id': 'cortex_xdr_' + kind.lower(),
                'integration_id': 'cortex_xdr',
                'display_name': cx_name,
                'address': cx_url,
                'host': host,
                'host_ip': hip,
                'data_kind': kind,
                'last_push_at': detail.get(kind) or None,
                'last_attempt_at': attempt.get('at') or None,
                'last_attempt_ok': attempt.get('ok') if attempt else None,
                'last_attempt_message': attempt.get('message') or None,
                'last_attempt_count': attempt.get('count') if attempt else None,
            })

    if _google_secops_is_configured(_get):
        g_addr, g_host = _google_secops_push_display_address(_get)
        gs_name = (_get('google_secops_display_name') or '').strip() or 'Google SecOps'
        detail_g = _parse_vendor_push_detail_json(_get(KEY_VENDOR_PUSH_DETAIL_GOOGLE) or '')
        hip_g = _resolve_hostname_ip(g_host)
        for kind in ('IOC', 'YARA'):
            attempt_g = _vendor_attempt_for_kind(_get, 'google_secops', kind)
            rows.append({
                'id': 'google_secops_' + kind.lower(),
                'integration_id': 'google_secops',
                'display_name': gs_name,
                'address': g_addr,
                'host': g_host,
                'host_ip': hip_g,
                'data_kind': kind,
                'last_push_at': detail_g.get(kind) or None,
                'last_attempt_at': attempt_g.get('at') or None,
                'last_attempt_ok': attempt_g.get('ok') if attempt_g else None,
                'last_attempt_message': attempt_g.get('message') or None,
                'last_attempt_count': attempt_g.get('count') if attempt_g else None,
            })

    return rows


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


def _build_pull_state_entries(_get):
    """
    Inbound IOC pulls: ZIoCHub connects outward to external platforms and imports into the DB.
    Currently MISP only (manual sync + misp_sync_job). Uses misp_last_sync / misp_last_sync_result.
    """
    url = (_get('misp_url') or '').strip()
    enabled = (_get('misp_enabled') or 'false').lower() == 'true'
    last_str = (_get('misp_last_sync') or '').strip()
    result_raw = _get('misp_last_sync_result')
    sync_status = 'unknown'
    if result_raw:
        try:
            r = json.loads(result_raw)
            if isinstance(r, dict):
                sync_status = 'ok' if r.get('success') else 'fail'
        except Exception:
            sync_status = 'unknown'

    if not url:
        return [{
            'id': 'misp',
            'name': 'MISP',
            'address': '',
            'host': '',
            'last_pull_at': None,
            'status': 'not_configured',
            'enabled': False,
        }]

    row = {
        'id': 'misp',
        'name': 'MISP',
        'address': url,
        'host': _host_from_url(url),
        'last_pull_at': last_str or None,
        'enabled': enabled,
    }
    if not enabled:
        row['status'] = 'disabled'
        return [row]

    row['status'] = sync_status
    return [row]


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
    pull_state = _build_pull_state_entries(_get)
    push_state = _build_integration_push_state_entries(_get)

    def _feed_product_type(feed_path: str) -> str:
        p = (feed_path or '').strip()
        if p.startswith('/taxii2'):
            return 'TAXII 2.1'
        # FEED buckets
        if p.startswith('/feed/pa/'):
            return 'Palo Alto EDL'
        if p.startswith('/feed/cp/'):
            return 'Check Point CSV'
        if p.startswith('/feed/esa/'):
            return 'Cisco ESA'
        if p.startswith('/feed/epo/'):
            return 'Trellix ePO'
        if p.startswith('/feed/stix'):
            return 'STIX 2.1 (bundle)'
        if p.startswith('/feed/yara'):
            return 'YARA feed'
        if p.startswith('/feed/'):
            return 'Generic feed'
        return '—'

    def _feed_value_kind(feed_path: str) -> str:
        p = (feed_path or '').strip()
        if p.startswith('/feed/yara'):
            return 'YARA'
        # TAXII and STIX expose IOCs (indicators) only
        return 'IOC'

    feed_access = [
        x for x in (
            {
                'client_ip': r.client_ip,
                'feed_path': r.feed_path,
                'last_seen_at': r.last_seen_at.isoformat() if r.last_seen_at else None,
                'last_status_code': getattr(r, 'last_status_code', None),
                'last_ok': getattr(r, 'last_ok', None),
            }
            for r in rows
        )
        if ((x.get('feed_path') or '').startswith('/feed')
            or (x.get('feed_path') or '').startswith('/taxii2'))
    ]

    feed_clients = [
        {
            # "Product name" per spec: show the connecting address (client IP)
            'product_name': x.get('client_ip') or 'unknown',
            'product_type': _feed_product_type(x.get('feed_path') or ''),
            'value_kind': _feed_value_kind(x.get('feed_path') or ''),
            'uri': x.get('feed_path') or '',
            'last_connection_at': x.get('last_seen_at'),
        }
        for x in feed_access
    ]

    # Newest first
    feed_clients.sort(key=lambda r: _parse_iso_ts(r.get('last_connection_at')) or datetime.min, reverse=True)

    return {
        'pull_state': pull_state,
        'push_state': push_state,
        # Backward compatible (used by older UI)
        'feed_access': feed_access,
        # New UI table (Feed Pulse → Connections)
        'feed_clients': feed_clients,
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
