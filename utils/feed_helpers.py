"""
Helpers for feed generation (Standard, Palo Alto, Checkpoint).
"""
from __future__ import annotations

from typing import Any


def strip_url_protocol(url: str | None) -> str | None:
    """Remove http:// or https:// from URL for Palo Alto feeds."""
    if not url:
        return url
    url = url.strip()
    if url.startswith('https://'):
        return url[8:]
    if url.startswith('http://'):
        return url[7:]
    return url


def _checkpoint_url_variants(url: str) -> list[str]:
    """
    For Check Point URL feed only: emit both http:// and https:// variants of the same URL,
    without persisting duplicates in DB.
    """
    u = (url or '').strip()
    if not u:
        return []
    tail = u
    if tail.lower().startswith('https://'):
        tail = tail[8:]
    elif tail.lower().startswith('http://'):
        tail = tail[7:]
    # Preserve the tail exactly as stored (case/path), only swap scheme.
    return [f'http://{tail}', f'https://{tail}']


def get_hash_type(hash_value: str | None) -> str | None:
    """Determine hash type based on length: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)."""
    if not hash_value:
        return None
    hash_len = len(hash_value.strip())
    if hash_len == 32:
        return 'md5'
    if hash_len == 40:
        return 'sha1'
    if hash_len == 64:
        return 'sha256'
    if hash_len == 128:
        return 'sha512'
    return None


def format_checkpoint_feed(rows: list[Any], ioc_type: str) -> str:
    """Format IOC rows as Checkpoint feed with header and observe numbers."""
    if not rows:
        return "#Uniq-Name,#Value,#Type,#Confidence,#Severity,#Product,#Comment\n"

    cp_type_map = {
        'IP': 'ip',
        'Domain': 'domain',
        'URL': 'url',
        'Hash': None,
    }
    lines = ["#Uniq-Name,#Value,#Type,#Confidence,#Severity,#Product,#Comment"]
    observe_num = 1
    for row in rows:
        value = (row.value or '').strip()
        if not value:
            continue
        if ioc_type == 'Hash':
            hash_type = get_hash_type(value)
            if not hash_type:
                continue
            cp_type = hash_type
        else:
            cp_type = cp_type_map.get(ioc_type, 'ip')
        comment = f'"""Malicious {cp_type.upper()}"""'

        # Check Point URL feed requirement: emit both http and https for each stored URL
        if ioc_type == 'URL':
            for v in _checkpoint_url_variants(value):
                line = f"observe{observe_num},{v},{cp_type},high,high,AV,{comment}"
                lines.append(line)
                observe_num += 1
        else:
            line = f"observe{observe_num},{value},{cp_type},high,high,AV,{comment}"
            lines.append(line)
            observe_num += 1
    return '\n'.join(lines) + '\n'
