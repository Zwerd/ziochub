"""
IOC validation and type detection.
"""
from __future__ import annotations

import re

# Strict regex patterns for validation
# URL: http(s), ftp, sftp with path/query; Domain: hostname only (must contain a dot + TLD)
# Hash: MD5(32), SHA1(40), SHA256(64), SHA512(128) hex chars
REGEX_PATTERNS = {
    'IP': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'Domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    'Hash': r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$',
    'Email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'URL': r'^(?:https?|ftp|sftp)://(?:[-\w.@])+(?:\:[0-9]+)?(?:\/[^\s#?]*(?:\?[^\s#]*)?(?:\#[^\s]*)?)?$',
}

AUTO_DETECT_PATTERNS = {
    'IP': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'Domain': r'(?<!@)\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    'Hash': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{128}\b',
    'Email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    'URL': r'(?:https?|ftp|sftp)://(?:[-\w.@])+(?:\:[0-9]+)?(?:/(?:[\w/_.~&=%-])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?',
}

PRIORITY_ORDER = ['URL', 'Email', 'IP', 'Hash', 'Domain']


def validate_ioc(value: str, ioc_type: str) -> bool:
    """Validate IOC value against strict regex pattern."""
    pattern = REGEX_PATTERNS.get(ioc_type)
    if not pattern:
        return False
    return bool(re.match(pattern, value.strip()))


def detect_ioc_type(value: str) -> str | None:
    """Auto-detect IOC type from value. URLs (http/https/ftp/sftp) are detected as URL, not Domain."""
    value = value.strip()
    if value.lower().startswith(('http://', 'https://', 'ftp://', 'sftp://')):
        return 'URL'
    for ioc_type in PRIORITY_ORDER:
        pattern = REGEX_PATTERNS.get(ioc_type)
        if pattern and re.match(pattern, value):
            return ioc_type
    return None
