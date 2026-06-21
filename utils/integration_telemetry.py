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
from typing import Any
from urllib.parse import urlparse

from flask import has_request_context, request

from extensions import db
from models import FeedSourceLastSeen, SystemSetting, _utcnow
from utils.downstream import (
    build_feed_client_lookup_by_ip,
    vendor_icon_url,
    vendor_meta_for_integration,
)

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
KEY_VENDOR_PUSH_DETAIL_NETSKOPE = 'telemetry_vendor_push_detail_netskope'
KEY_VENDOR_PUSH_DETAIL_ESA = 'telemetry_vendor_push_detail_cisco_esa'

# Vendor push attempts (last attempt, regardless of success) for Push State table
KEY_VENDOR_PUSH_ATTEMPT_CORTEX = 'telemetry_vendor_push_attempt_cortex_xdr'
KEY_VENDOR_PUSH_ATTEMPT_GOOGLE = 'telemetry_vendor_push_attempt_google_secops'
KEY_VENDOR_PUSH_ATTEMPT_NETSKOPE = 'telemetry_vendor_push_attempt_netskope'
KEY_VENDOR_PUSH_ATTEMPT_ESA = 'telemetry_vendor_push_attempt_cisco_esa'

# Outbound push kinds ZIoCHub actually supports per vendor (Push State rows).
_VENDOR_PUSH_DATA_KINDS: dict[str, tuple[str, ...]] = {
    'cortex_xdr': ('IOC',),  # Cortex XDR API: IOC/blocklist only — no YARA push
    'google_secops': ('IOC',),  # Chronicle/SecOps: IOC indicators only — no YARA / YARA-L push
    'netskope': ('IOC',),  # Netskope SWG URL List + File Hash List
    'cisco_esa': ('IOC',),
    'misp_push': ('IOC',),
    'opendxl': ('IOC',),  # Hash reputation via TIE only
}


def _push_kinds_for_vendor(vendor_id: str) -> tuple[str, ...]:
    return _VENDOR_PUSH_DATA_KINDS.get((vendor_id or '').strip(), ('IOC',))


def _vendor_supports_push_kind(vendor_id: str, data_kind: str) -> bool:
    kind_u = (data_kind or '').strip().upper()
    return kind_u in _push_kinds_for_vendor(vendor_id)


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
        try:
            from utils.downstream import correlate_feed_pull
            correlate_feed_pull(ip, path, ts, ok)
        except Exception:
            logger.debug('correlate_feed_pull hook failed', exc_info=True)
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
    vid = (vendor_id or '').strip()
    if not _vendor_supports_push_kind(vid, kind_u):
        return
    key_map = {
        'cortex_xdr': KEY_VENDOR_PUSH_DETAIL_CORTEX,
        'google_secops': KEY_VENDOR_PUSH_DETAIL_GOOGLE,
        'netskope': KEY_VENDOR_PUSH_DETAIL_NETSKOPE,
        'cisco_esa': KEY_VENDOR_PUSH_DETAIL_ESA,
    }
    setting_key = key_map.get(vid)
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
    if vendor_id == 'netskope' and ('skipped_incomplete_config' in m or m == 'disabled'):
        return
    if vendor_id == 'cisco_esa' and (m.startswith('skipped') or m.startswith('nothing to')):
        return
    record_vendor_integration_push(vendor_id, 'IOC')


def vendor_batch_summary_message(
    succeeded: int,
    failed: int,
    processed: int,
    all_failed: list,
) -> str:
    """Batch push summary for Feed Pulse; appends the first failure detail when present."""
    msg = f'batch ok={succeeded} fail={failed} total={processed}'
    if not all_failed:
        return msg
    err = str(all_failed[0][1] or '').strip()
    if not err:
        return msg
    budget = 240 - len(msg) - 2
    if budget > 16:
        msg = f'{msg}; {err[:budget]}'
    return msg


def record_vendor_push_attempt(vendor_id: str, *, data_kind: str = 'IOC', ok: bool, message: str = '', count: int | None = None) -> None:
    """
    Record last outbound push attempt to a built-in vendor integration (Cortex XDR, Google SecOps).
    Unlike `record_vendor_integration_push`, this stores success/failure + a short reason + optional count.
    """
    kind_u = (data_kind or '').strip().upper()
    if kind_u not in ('IOC', 'YARA'):
        kind_u = 'IOC'
    vid = (vendor_id or '').strip()
    if not _vendor_supports_push_kind(vid, kind_u):
        return
    key_map = {
        'cortex_xdr': KEY_VENDOR_PUSH_ATTEMPT_CORTEX,
        'google_secops': KEY_VENDOR_PUSH_ATTEMPT_GOOGLE,
        'netskope': KEY_VENDOR_PUSH_ATTEMPT_NETSKOPE,
        'cisco_esa': KEY_VENDOR_PUSH_ATTEMPT_ESA,
    }
    setting_key = key_map.get(vid)
    if not setting_key:
        return
    try:
        now = _utcnow().isoformat()
        attempt_payload = {
            'at': now,
            'ok': bool(ok),
            'kind': kind_u,
            'count': int(count) if isinstance(count, int) else None,
            'message': (str(message or '')[:240]),
        }
        s = SystemSetting.query.filter_by(key=setting_key).first()
        raw = (s.value if s else '') or '{}'
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            obj = {}
        if not isinstance(obj, dict):
            obj = {}
        # Per-kind map (IOC / YARA) so Push State can show both rows without overwriting.
        if 'at' in obj and 'kind' in obj and not any(k in obj for k in ('IOC', 'YARA')):
            legacy_kind = (obj.get('kind') or 'IOC').upper()
            obj = {legacy_kind: {k: v for k, v in obj.items() if k != 'kind'}}
        obj[kind_u] = attempt_payload
        val = json.dumps(obj, ensure_ascii=False)
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
        'netskope': KEY_VENDOR_PUSH_ATTEMPT_NETSKOPE,
        'cisco_esa': KEY_VENDOR_PUSH_ATTEMPT_ESA,
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
    kind_key = (kind_u or '').upper()
    nested = obj.get(kind_key)
    if isinstance(nested, dict) and nested.get('at'):
        return nested
    # Legacy flat payload: {"at", "ok", "kind", ...}
    if obj.get('at') and (obj.get('kind') or 'IOC').upper() == kind_key:
        return obj
    return {}


def _google_secops_push_display_address(_get) -> tuple[str, str]:
    """Return (display_url_or_label, hostname) for Chronicle API or API Gateway."""
    from utils.google_secops import CONNECTION_MODE_APIGEE, google_secops_connection_mode

    mode = google_secops_connection_mode({
        'google_secops_connection_mode': _get('google_secops_connection_mode') or 'direct',
    })
    if mode == CONNECTION_MODE_APIGEE:
        raw_base = (_get('google_secops_gateway_base_url') or '').strip().rstrip('/')
        if raw_base:
            return raw_base, _host_from_url(raw_base)
        return '', ''
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
    from utils.google_secops import (
        CONNECTION_MODE_APIGEE,
        GATEWAY_AUTH_API_KEY,
        GATEWAY_AUTH_OAUTH2,
        google_secops_connection_mode,
        google_secops_gateway_auth_method,
    )

    proj = (_get('google_secops_project_number') or '').strip()
    loc = (_get('google_secops_location') or '').strip()
    inst = (_get('google_secops_instance_id') or '').strip() or (_get('google_secops_customer_id') or '').strip()
    tid = (_get('google_secops_data_table_id') or '').strip()
    if not (proj and loc and inst and tid):
        return False

    g = {'google_secops_connection_mode': _get('google_secops_connection_mode') or 'direct'}
    if google_secops_connection_mode(g) == CONNECTION_MODE_APIGEE:
        if not (_get('google_secops_gateway_base_url') or '').strip():
            return False
        auth = google_secops_gateway_auth_method({
            'google_secops_gateway_auth_method': _get('google_secops_gateway_auth_method') or GATEWAY_AUTH_API_KEY,
        })
        if auth == GATEWAY_AUTH_OAUTH2:
            return bool(
                (_get('google_secops_gateway_oauth_token_url') or '').strip()
                and (_get('google_secops_gateway_oauth_client_id') or '').strip()
                and (_get('google_secops_gateway_oauth_client_secret') or '').strip()
            )
        return bool((_get('google_secops_gateway_api_key') or '').strip())

    creds = (_get('google_secops_credentials_json') or '').strip()
    base_ok = bool((_get('google_secops_chronicle_api_base') or '').strip() or loc)
    return bool(creds and base_ok)


def _norm_automation_url(url: str) -> str:
    return (url or '').strip().lower().rstrip('/')


def _esa_is_configured(_get) -> bool:
    base = (_get('esa_base_url') or '').strip()
    enabled = (_get('esa_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    user = (_get('esa_username') or '').strip()
    return bool((base or enabled) and user)


def build_automation_url_vendor_lookup(_get) -> dict[str, dict[str, Any]]:
    """
    Map normalized push/upload URL → vendor icon/label for built-in YARA automation targets
    (FireEye HTTP, Trellix NX/EX/CMS). Generic IOC push URLs are not included.
    """
    import json

    from utils.downstream import vendor_meta_for_integration
    from utils.trellix_cms import list_trellix_cms_targets
    from utils.trellix_ex import list_trellix_ex_targets, trellix_ex_upload_url_for_target
    from utils.trellix_nx import (
        expand_trellix_nx_targets,
        list_nx_wmps_session_targets,
        parse_trellix_nx_targets_json,
        trellix_nx_enabled,
    )
    from utils.yara_http_push import appliance_upload_url

    lookup: dict[str, dict[str, Any]] = {}

    def _add(url: str, integration_id: str, *, target_name: str = '', configured: bool = True) -> None:
        raw = (url or '').strip()
        key = _norm_automation_url(raw)
        if not key:
            return
        meta = vendor_meta_for_integration(integration_id)
        lookup[key] = {
            **meta,
            'url': raw,
            'target_name': (target_name or '').strip() or meta.get('integration_label') or '—',
            'configured': configured,
        }

    fe_enabled = (_get('automation_fireeye_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    raw_fe = (_get('automation_fireeye_appliances') or '[]').strip()
    try:
        fe_apps = json.loads(raw_fe) if raw_fe else []
    except (json.JSONDecodeError, TypeError):
        fe_apps = []
    if fe_enabled or (isinstance(fe_apps, list) and fe_apps):
        for app in fe_apps if isinstance(fe_apps, list) else []:
            if not isinstance(app, dict):
                continue
            upload = appliance_upload_url(app)
            _add(
                upload,
                'fireeye_yara',
                target_name=(app.get('name') or '').strip() or 'FireEye / Trellix',
                configured=fe_enabled,
            )

    nx_on = trellix_nx_enabled(_get)
    nx_raw = parse_trellix_nx_targets_json(_get('automation_trellix_nx_targets') or '[]')
    if nx_on or nx_raw:
        for app in expand_trellix_nx_targets(nx_raw):
            upload = appliance_upload_url(app)
            _add(
                upload,
                'trellix_nx',
                target_name=(app.get('name') or '').strip() or 'Trellix NX',
                configured=nx_on,
            )
        for t in list_nx_wmps_session_targets(_get):
            upload = trellix_ex_upload_url_for_target(t)
            _add(
                upload,
                'trellix_nx',
                target_name=(t.get('name') or '').strip() or 'Trellix NX (wmps)',
                configured=nx_on,
            )

    ex_on = (_get('trellix_ex_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    ex_targets = list_trellix_ex_targets(_get)
    if ex_on or ex_targets:
        for t in ex_targets:
            upload = trellix_ex_upload_url_for_target(t)
            _add(
                upload,
                'trellix_ex',
                target_name=(t.get('name') or '').strip() or 'Trellix Email Security',
                configured=ex_on,
            )

    cms_on = (_get('trellix_cms_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    cms_targets = list_trellix_cms_targets(_get)
    if cms_on or cms_targets:
        for t in cms_targets:
            upload = trellix_ex_upload_url_for_target(t)
            _add(
                upload,
                'trellix_cms',
                target_name=(t.get('name') or '').strip() or 'Trellix CMS',
                configured=cms_on,
            )

    return lookup


def resolve_automation_target_vendor(
    url: str,
    name: str,
    lookup: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Resolve vendor icon for an automation telemetry row (built-in product or generic)."""
    from utils.downstream import vendor_icon_url

    generic = vendor_icon_url('generic')
    lu = lookup or {}
    key = _norm_automation_url(url)
    if key and key in lu:
        return lu[key]
    name_l = (name or '').strip().lower()
    if name_l:
        for meta in lu.values():
            if (meta.get('target_name') or '').strip().lower() == name_l:
                return meta
    if key:
        for k, meta in lu.items():
            if key.startswith(k) or k.startswith(key):
                return meta
    return {
        'registered': False,
        'vendor_label': '',
        'vendor_icon_url': generic,
        'integration_id': None,
        'integration_label': 'HTTP automation',
    }


def _merge_configured_automation_targets(
    _get,
    telemetry_rows: list[dict[str, Any]],
    url_lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Add configured built-in YARA targets that have not recorded a push attempt yet."""
    seen = {_norm_automation_url(r.get('url') or '') for r in telemetry_rows}
    out = list(telemetry_rows)
    for key, meta in url_lookup.items():
        if not meta.get('configured'):
            continue
        if key in seen:
            continue
        raw_url = meta.get('url') or key
        out.append({
            'name': meta.get('target_name') or '—',
            'url': raw_url,
            'host': _host_from_url(raw_url),
            'last_seen_at': None,
            'kinds': [],
            'status': 'never',
            'vendor_label': meta.get('vendor_label', ''),
            'vendor_icon_url': meta.get('vendor_icon_url', ''),
            'integration_id': meta.get('integration_id'),
            'integration_label': meta.get('integration_label', ''),
        })
    return out


def _build_integration_push_state_entries(_get):
    """
    Outbound vendor integrations (Admin → Integrations): Cortex XDR, Google SecOps, Cisco ESA.
    One flat row per (system, data kind) with last push time (IOC/YARA tracked separately in JSON).
    """
    rows = []

    cx_url = (_get('cortex_xdr_base_url') or '').strip()
    cx_enabled = (_get('cortex_xdr_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    cx_name = (_get('cortex_xdr_display_name') or '').strip() or 'Cortex XDR'
    if cx_url or cx_enabled:
        detail = _parse_vendor_push_detail_json(_get(KEY_VENDOR_PUSH_DETAIL_CORTEX) or '')
        host = _host_from_url(cx_url) if cx_url else ''
        hip = _resolve_hostname_ip(host) if host else ''
        for kind in _push_kinds_for_vendor('cortex_xdr'):
            attempt = _vendor_attempt_for_kind(_get, 'cortex_xdr', kind)
            cx_vendor = vendor_meta_for_integration('cortex_xdr')
            rows.append({
                'id': 'cortex_xdr_' + kind.lower(),
                'integration_id': 'cortex_xdr',
                'display_name': cx_name,
                'address': cx_url or '(not configured)',
                'host': host,
                'host_ip': hip,
                'data_kind': kind,
                'enabled': cx_enabled,
                'vendor_label': cx_vendor['vendor_label'],
                'vendor_icon_url': cx_vendor['vendor_icon_url'],
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
        for kind in _push_kinds_for_vendor('google_secops'):
            attempt_g = _vendor_attempt_for_kind(_get, 'google_secops', kind)
            gs_vendor = vendor_meta_for_integration('google_secops')
            rows.append({
                'id': 'google_secops_' + kind.lower(),
                'integration_id': 'google_secops',
                'display_name': gs_name,
                'address': g_addr,
                'host': g_host,
                'host_ip': hip_g,
                'data_kind': kind,
                'vendor_label': gs_vendor['vendor_label'],
                'vendor_icon_url': gs_vendor['vendor_icon_url'],
                'last_push_at': detail_g.get(kind) or None,
                'last_attempt_at': attempt_g.get('at') or None,
                'last_attempt_ok': attempt_g.get('ok') if attempt_g else None,
                'last_attempt_message': attempt_g.get('message') or None,
                'last_attempt_count': attempt_g.get('count') if attempt_g else None,
            })

    ns_url = (_get('netskope_base_url') or '').strip()
    ns_enabled = (_get('netskope_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    if ns_url or ns_enabled:
        from utils.netskope import sanitize_netskope_base_url
        ns_name = (_get('netskope_display_name') or '').strip() or 'Netskope'
        ns_addr = sanitize_netskope_base_url(ns_url) if ns_url else ''
        ns_host = _host_from_url(ns_addr) if ns_addr else ''
        ns_hip = _resolve_hostname_ip(ns_host) if ns_host else ''
        detail_ns = _parse_vendor_push_detail_json(_get(KEY_VENDOR_PUSH_DETAIL_NETSKOPE) or '')
        ns_vendor = vendor_meta_for_integration('netskope')
        for kind in _push_kinds_for_vendor('netskope'):
            attempt_ns = _vendor_attempt_for_kind(_get, 'netskope', kind)
            rows.append({
                'id': 'netskope_' + kind.lower(),
                'integration_id': 'netskope',
                'display_name': ns_name,
                'address': ns_addr or '(not configured)',
                'host': ns_host,
                'host_ip': ns_hip,
                'data_kind': kind,
                'enabled': ns_enabled,
                'vendor_label': ns_vendor['vendor_label'],
                'vendor_icon_url': ns_vendor['vendor_icon_url'],
                'last_push_at': detail_ns.get(kind) or None,
                'last_attempt_at': attempt_ns.get('at') or None,
                'last_attempt_ok': attempt_ns.get('ok') if attempt_ns else None,
                'last_attempt_message': attempt_ns.get('message') or None,
                'last_attempt_count': attempt_ns.get('count') if attempt_ns else None,
            })

    esa_base = (_get('esa_base_url') or '').strip()
    esa_enabled = (_get('esa_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    if esa_base or esa_enabled or _esa_is_configured(_get):
        esa_name = 'Cisco ESA (IronPort)'
        detail_esa = _parse_vendor_push_detail_json(_get(KEY_VENDOR_PUSH_DETAIL_ESA) or '')
        host_esa = _host_from_url(esa_base) if esa_base else ''
        hip_esa = _resolve_hostname_ip(host_esa) if host_esa else ''
        esa_vendor = vendor_meta_for_integration('cisco_esa')
        for kind in _push_kinds_for_vendor('cisco_esa'):
            attempt_esa = _vendor_attempt_for_kind(_get, 'cisco_esa', kind)
            rows.append({
                'id': 'cisco_esa_' + kind.lower(),
                'integration_id': 'cisco_esa',
                'display_name': esa_name,
                'address': esa_base or '(not configured)',
                'host': host_esa,
                'host_ip': hip_esa,
                'data_kind': kind,
                'enabled': esa_enabled,
                'vendor_label': esa_vendor['vendor_label'],
                'vendor_icon_url': esa_vendor['vendor_icon_url'],
                'last_push_at': detail_esa.get(kind) or None,
                'last_attempt_at': attempt_esa.get('at') or None,
                'last_attempt_ok': attempt_esa.get('ok') if attempt_esa else None,
                'last_attempt_message': attempt_esa.get('message') or None,
                'last_attempt_count': attempt_esa.get('count') if attempt_esa else None,
            })

    misp_url = (_get('misp_url') or '').strip()
    misp_push_enabled = (_get('misp_push_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    if misp_url or misp_push_enabled:
        misp_vendor = vendor_meta_for_integration('misp_push')
        host_misp = _host_from_url(misp_url) if misp_url else ''
        hip_misp = _resolve_hostname_ip(host_misp) if host_misp else ''
        for kind in _push_kinds_for_vendor('misp_push'):
            rows.append({
                'id': 'misp_push_' + kind.lower(),
                'integration_id': 'misp_push',
                'display_name': 'MISP',
                'address': misp_url or '(not configured)',
                'host': host_misp,
                'host_ip': hip_misp,
                'data_kind': kind,
                'enabled': misp_push_enabled,
                'vendor_label': misp_vendor['vendor_label'],
                'vendor_icon_url': misp_vendor['vendor_icon_url'],
                'last_push_at': None,
                'last_attempt_at': None,
                'last_attempt_ok': None,
                'last_attempt_message': None,
                'last_attempt_count': None,
            })

    dxl_cfg = (_get('dxl_config_path') or '').strip()
    dxl_enabled = (_get('dxl_enabled') or 'false').strip().lower() in ('true', '1', 'yes')
    if dxl_cfg or dxl_enabled:
        dxl_vendor = vendor_meta_for_integration('opendxl')
        last_dxl = (_get(KEY_DXL) or '').strip() or None
        for kind in _push_kinds_for_vendor('opendxl'):
            rows.append({
                'id': 'opendxl_' + kind.lower(),
                'integration_id': 'opendxl',
                'display_name': 'OpenDXL / Trellix TIE',
                'address': dxl_cfg or '(not configured)',
                'host': '',
                'host_ip': '',
                'data_kind': kind,
                'enabled': dxl_enabled,
                'vendor_label': dxl_vendor['vendor_label'],
                'vendor_icon_url': dxl_vendor['vendor_icon_url'],
                'last_push_at': last_dxl,
                'last_attempt_at': last_dxl,
                'last_attempt_ok': True if last_dxl else None,
                'last_attempt_message': None,
                'last_attempt_count': None,
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


def _parse_pull_sync_result(result_raw) -> tuple[str, str]:
    sync_status = 'unknown'
    last_summary = ''
    if result_raw:
        try:
            r = json.loads(result_raw)
            if isinstance(r, dict):
                if r.get('success'):
                    sync_status = 'ok'
                    parts = []
                    if r.get('added') is not None:
                        parts.append(f"added={r.get('added', 0)}")
                    if r.get('skipped') is not None:
                        parts.append(f"skipped={r.get('skipped', 0)}")
                    if r.get('fetched') is not None:
                        parts.append(f"fetched={r.get('fetched', 0)}")
                    last_summary = ', '.join(parts) if parts else 'ok'
                else:
                    sync_status = 'fail'
                    last_summary = (r.get('error') or 'sync failed')[:240]
        except Exception:
            sync_status = 'unknown'
    return sync_status, last_summary


def _enrich_pull_row_vendor(row: dict, integration_id: str) -> dict:
    """Attach vendor icon/label for configured inbound pull sources."""
    if (row.get('status') or '') == 'not_configured' and not (row.get('address') or '').strip():
        return row
    vendor = vendor_meta_for_integration(integration_id)
    row['integration_id'] = integration_id
    row['vendor_label'] = vendor['vendor_label']
    row['vendor_icon_url'] = vendor['vendor_icon_url']
    return row


def _misp_pull_state_row(_get) -> dict:
    from utils.misp_sync_runner import (
        MISP_PULL_INTERVAL_DEFAULT,
        next_misp_pull_at,
        normalize_misp_pull_interval,
    )

    url = (_get('misp_url') or '').strip()
    enabled = (_get('misp_enabled') or 'false').lower() == 'true'
    last_str = (_get('misp_last_sync') or '').strip()
    pull_interval_min = normalize_misp_pull_interval(
        _get('misp_pull_interval') or str(MISP_PULL_INTERVAL_DEFAULT)
    )
    sync_status, last_summary = _parse_pull_sync_result(_get('misp_last_sync_result'))
    nxt = next_misp_pull_at(_get) if enabled and last_str else None

    if not url:
        return _enrich_pull_row_vendor({
            'id': 'misp',
            'name': 'MISP',
            'address': '',
            'host': '',
            'last_pull_at': None,
            'next_pull_at': None,
            'pull_interval_min': pull_interval_min,
            'last_summary': '',
            'status': 'not_configured',
            'enabled': False,
        }, 'misp_pull')

    row = {
        'id': 'misp',
        'name': 'MISP',
        'address': url,
        'host': _host_from_url(url),
        'last_pull_at': last_str or None,
        'next_pull_at': nxt,
        'pull_interval_min': pull_interval_min,
        'last_summary': last_summary,
        'enabled': enabled,
        'status': 'disabled' if not enabled else sync_status,
    }
    return _enrich_pull_row_vendor(row, 'misp_pull')


def _taxii_pull_state_row(_get) -> dict:
    from utils.taxii_sync_runner import (
        TAXII_PULL_INTERVAL_DEFAULT,
        next_taxii_pull_at,
        normalize_taxii_pull_interval,
    )

    url = (_get('taxii_discovery_url') or '').strip()
    enabled = (_get('taxii_pull_enabled') or 'false').lower() == 'true'
    last_str = (_get('taxii_last_sync') or '').strip()
    pull_interval_min = normalize_taxii_pull_interval(
        _get('taxii_pull_interval') or str(TAXII_PULL_INTERVAL_DEFAULT)
    )
    sync_status, last_summary = _parse_pull_sync_result(_get('taxii_last_sync_result'))
    nxt = next_taxii_pull_at(_get) if enabled and last_str else None
    api_key = (_get('taxii_api_key') or '').strip()
    user = (_get('taxii_username') or '').strip()
    pwd = (_get('taxii_password') or '').strip()
    has_creds = bool(api_key or (user and pwd))

    if not url or not has_creds:
        return {
            'id': 'taxii',
            'name': 'TAXII (remote)',
            'address': url or '',
            'host': _host_from_url(url) if url else '',
            'last_pull_at': None,
            'next_pull_at': None,
            'pull_interval_min': pull_interval_min,
            'last_summary': '',
            'status': 'not_configured',
            'enabled': False,
        }

    return {
        'id': 'taxii',
        'name': 'TAXII (remote)',
        'address': url,
        'host': _host_from_url(url),
        'last_pull_at': last_str or None,
        'next_pull_at': nxt,
        'pull_interval_min': pull_interval_min,
        'last_summary': last_summary,
        'enabled': enabled,
        'status': 'disabled' if not enabled else sync_status,
    }


def _build_pull_state_entries(_get):
    """
    Inbound IOC pulls: ZIoCHub connects outward to MISP and/or remote TAXII 2.1 servers.
    """
    return [_misp_pull_state_row(_get), _taxii_pull_state_row(_get)]


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

    def _get(key, default=None):
        """Read SystemSetting; optional ``default`` for MISP scheduler helpers (``next_misp_pull_at``)."""
        s = SystemSetting.query.filter_by(key=key).first()
        if not s:
            return default
        v = (s.value or '').strip()
        if not v:
            return default
        return v

    automation_targets = _build_automation_targets(_get)
    automation_vendor_lookup = build_automation_url_vendor_lookup(_get)
    automation_targets = _merge_configured_automation_targets(_get, automation_targets, automation_vendor_lookup)
    for row in automation_targets:
        vendor = resolve_automation_target_vendor(
            row.get('url') or '',
            row.get('name') or '',
            automation_vendor_lookup,
        )
        row['vendor_label'] = vendor.get('vendor_label', '')
        row['vendor_icon_url'] = vendor.get('vendor_icon_url', '')
        row['integration_id'] = vendor.get('integration_id')
        row['integration_label'] = vendor.get('integration_label', '')
        row['downstream_registered'] = bool(vendor.get('integration_id'))
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

    feed_clients = []
    downstream_by_ip = build_feed_client_lookup_by_ip()
    for x in feed_access:
        ip = x.get('client_ip') or 'unknown'
        info = downstream_by_ip.get(ip)
        if info:
            system_name = info['system_name']
            vendor_label = info['vendor_label']
            vendor_icon = info['vendor_icon_url']
            registered = True
        else:
            system_name = ip
            vendor_label = ''
            vendor_icon = vendor_icon_url('generic')
            registered = False
        feed_clients.append({
            'client_ip': ip,
            'system_name': system_name,
            'downstream_registered': registered,
            'vendor_label': vendor_label,
            'vendor_icon_url': vendor_icon,
            # Backward compatible: product_name was client IP; now admin display name when known
            'product_name': system_name,
            'product_type': _feed_product_type(x.get('feed_path') or ''),
            'value_kind': _feed_value_kind(x.get('feed_path') or ''),
            'uri': x.get('feed_path') or '',
            'last_connection_at': x.get('last_seen_at'),
        })

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
