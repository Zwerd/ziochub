"""
Simple in-memory TTL cache for expensive API responses (Champs leaderboard, team goal, Reports data).
Thread-safe for Flask's multi-threaded workers.
"""
import threading
import time


class TTLCache:
    """In-memory cache with TTL. Keys expire after ttl_seconds."""

    def __init__(self, default_ttl_seconds=120):
        self._store = {}
        self._expiry = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl_seconds

    def get(self, key):
        with self._lock:
            if key not in self._store:
                return None
            if time.monotonic() >= self._expiry[key]:
                del self._store[key]
                del self._expiry[key]
                return None
            return self._store[key]

    def set(self, key, value, ttl_seconds=None):
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        with self._lock:
            self._store[key] = value
            self._expiry[key] = time.monotonic() + ttl

    def delete(self, key):
        with self._lock:
            self._store.pop(key, None)
            self._expiry.pop(key, None)


# Singleton used by routes
_cache = TTLCache(default_ttl_seconds=120)


def get_cached(key):
    return _cache.get(key)


def set_cached(key, value, ttl_seconds=120):
    _cache.set(key, value, ttl_seconds=ttl_seconds)


def delete_cached(key):
    _cache.delete(key)
