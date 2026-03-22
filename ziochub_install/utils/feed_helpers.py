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


def get_hash_type(hash_value: str | None) -> str | None:
    """Determine hash type based on length: MD5 (32), SHA1 (40), SHA256 (64)."""
    if not hash_value:
        return None
    hash_len = len(hash_value.strip())
    if hash_len == 32:
        return 'md5'
    if hash_len == 40:
        return 'sha1'
    if hash_len == 64:
        return 'sha256'
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
        value = row.value.strip()
        if ioc_type == 'Hash':
            hash_type = get_hash_type(value)
            if not hash_type:
                continue
            cp_type = hash_type
        else:
            cp_type = cp_type_map.get(ioc_type, 'ip')
        comment = f'"""Malicious {cp_type.upper()}"""'
        line = f"observe{observe_num},{value},{cp_type},high,high,AV,{comment}"
        lines.append(line)
        observe_num += 1
    return '\n'.join(lines) + '\n'
