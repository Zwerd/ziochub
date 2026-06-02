"""
Parse STIX 2.1 indicator patterns into ZIoCHub IOC type + value (inverse of routes.feeds._stix_indicator_pattern).
"""
from __future__ import annotations

import re
from typing import Optional

# Order matters: more specific patterns first.
_PATTERN_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\[\s*ipv4-addr\s*:\s*value\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'IP'),
    (re.compile(r"\[\s*ipv6-addr\s*:\s*value\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'IP'),
    (re.compile(r"\[\s*domain-name\s*:\s*value\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Domain'),
    (re.compile(r"\[\s*url\s*:\s*value\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'URL'),
    (re.compile(r"\[\s*email-addr\s*:\s*value\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Email'),
    (re.compile(r"\[\s*file\s*:\s*hashes\s*\.\s*'MD5'\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Hash'),
    (re.compile(r"\[\s*file\s*:\s*hashes\s*\.\s*'SHA-1'\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Hash'),
    (re.compile(r"\[\s*file\s*:\s*hashes\s*\.\s*'SHA-256'\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Hash'),
    (re.compile(r"\[\s*file\s*:\s*hashes\s*\.\s*'SHA-512'\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Hash'),
    (re.compile(r"\[\s*file\s*:\s*hashes\s*\.\s*md5\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Hash'),
    (re.compile(r"\[\s*file\s*:\s*hashes\s*\.\s*'SHA1'\s*=\s*'((?:\\'|[^'])*)'\s*\]", re.I), 'Hash'),
]


def _unescape_stix_value(raw: str) -> str:
    return (raw or '').replace("\\'", "'").replace('\\\\', '\\').strip()


def parse_indicator_pattern(pattern: str) -> Optional[tuple[str, str]]:
    """
    Return (tg_type, value) or None if pattern is unsupported / empty.
    tg_type is one of IP, Domain, URL, Email, Hash.
    """
    p = (pattern or '').strip()
    if not p:
        return None
    for rx, tg_type in _PATTERN_RULES:
        m = rx.search(p)
        if not m:
            continue
        value = _unescape_stix_value(m.group(1))
        if not value:
            return None
        return tg_type, value
    return None
