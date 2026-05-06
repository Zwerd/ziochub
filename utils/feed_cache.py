"""
HTTP feed response cache in SQLite (shared across Gunicorn workers).
Controlled by Admin: feed_cache_enabled, feed_cache_ttl_seconds (preset list only).
"""
import json
import logging

from flask import Response

from extensions import db
from models import FeedCacheEntry, _utcnow

logger = logging.getLogger(__name__)

# Seconds: 1m, 5m, 10m, 15m, 30m, 1h, 12h-must match Admin UI presets
FEED_CACHE_TTL_PRESETS = (60, 300, 600, 900, 1800, 3600, 43200)
# Default when unset, invalid, or not in presets (save path)
FEED_CACHE_TTL_DEFAULT = 300


def _get_setting(key: str, default: str = '') -> str:
    import app as _app
    return _app._get_setting(key, default)


def normalize_feed_cache_ttl_seconds(raw: int) -> int:
    """Map stored TTL to a preset; unknown values snap to nearest preset."""
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return FEED_CACHE_TTL_DEFAULT
    if n in FEED_CACHE_TTL_PRESETS:
        return n
    return min(FEED_CACHE_TTL_PRESETS, key=lambda p: abs(p - n))


def feed_cache_config():
    """Return (enabled: bool, ttl_seconds: int)."""
    enabled = _get_setting('feed_cache_enabled', 'true').strip().lower() in ('true', '1', 'yes')
    try:
        ttl = int(_get_setting('feed_cache_ttl_seconds', '300') or '300')
    except ValueError:
        ttl = FEED_CACHE_TTL_DEFAULT
    ttl = normalize_feed_cache_ttl_seconds(ttl)
    return enabled, ttl


def clear_all_feed_cache():
    """Delete all cached feed bodies (e.g. after Admin changes cache settings)."""
    try:
        FeedCacheEntry.query.delete()
        import app as _app
        _app._commit_with_retry()
    except Exception:
        logger.warning('clear_all_feed_cache failed', exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def invalidate_feed_cache_after_ioc_change():
    """
    Call after IOC rows change membership of public text/STIX feeds (revoke, auto-expire, etc.).
    Cached /feed/* responses would otherwise serve stale indicators until TTL expires.
    """
    clear_all_feed_cache()


def get_cached_feed_response(cache_key: str):
    """
    Return a Flask Response if cache hit and fresh; else None.
    cache_key must be <= 512 chars.
    """
    if not cache_key or len(cache_key) > 512:
        return None
    enabled, ttl = feed_cache_config()
    if not enabled:
        return None
    try:
        row = db.session.get(FeedCacheEntry, cache_key)
        if not row or not row.body:
            return None
        age = (_utcnow() - row.updated_at).total_seconds()
        if age >= ttl:
            return None
        headers = {}
        if row.extra_headers_json:
            try:
                headers = json.loads(row.extra_headers_json)
            except (TypeError, ValueError):
                pass
        return Response(
            row.body,
            mimetype=row.content_type or 'text/plain',
            headers=headers,
        )
    except Exception:
        logger.debug('get_cached_feed_response failed for %s', cache_key[:80], exc_info=True)
        return None


def store_feed_response(cache_key: str, response: Response):
    """Persist a 200 response body if caching is enabled."""
    if not cache_key or len(cache_key) > 512:
        return
    if response is None or getattr(response, 'status_code', None) != 200:
        return
    enabled, _ = feed_cache_config()
    if not enabled:
        return
    try:
        raw = response.get_data()
        try:
            body = raw.decode('utf-8')
        except UnicodeDecodeError:
            body = raw.decode('utf-8', errors='replace')
        headers = {}
        for h in ('Content-Disposition', 'X-Content-Type-Options'):
            if h in response.headers:
                headers[h] = response.headers[h]
        extra = json.dumps(headers) if headers else None
        ct = response.mimetype or response.content_type or 'text/plain'
        if ';' in ct:
            ct = ct.split(';')[0].strip()
        import app as _app
        now = _utcnow()
        row = db.session.get(FeedCacheEntry, cache_key)
        if row:
            row.body = body
            row.content_type = ct[:255]
            row.extra_headers_json = extra
            row.updated_at = now
        else:
            db.session.add(FeedCacheEntry(
                cache_key=cache_key[:512],
                body=body,
                content_type=ct[:255],
                extra_headers_json=extra,
                updated_at=now,
            ))
        _app._commit_with_retry()
    except Exception:
        logger.warning('store_feed_response failed for %s', cache_key[:80], exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass


def serve_feed_cached(cache_key: str, builder):
    """
    Return cached Response if valid; else builder() -> Response, store if 200, return.
    builder is a callable taking no arguments.
    """
    cached = get_cached_feed_response(cache_key)
    if cached is not None:
        return cached
    resp = builder()
    try:
        store_feed_response(cache_key, resp)
    except Exception:
        pass
    return resp
