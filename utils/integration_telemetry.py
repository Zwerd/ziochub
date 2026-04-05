"""
Last-seen telemetry: /feed pulls (per client IP + path), API IOC ingest, YARA upload, DXL TIE push.
Used by Feed Pulse → Connections (no Linux log access required).
"""
import logging
import threading
import time

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


def _client_ip():
    if not has_request_context():
        return ''
    xff = (request.headers.get('X-Forwarded-For') or '').strip()
    if xff:
        return xff.split(',')[0].strip()[:45]
    return (request.remote_addr or '')[:45] or 'unknown'


def record_feed_pull_if_ok(response):
    """Record successful feed response (200). Throttled per (IP, path). Call from feeds after_request."""
    if not has_request_context():
        return
    try:
        if response is None or getattr(response, 'status_code', None) != 200:
            return
        path = request.path or ''
        if not path.startswith('/feed'):
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
    }
