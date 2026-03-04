"""
Input cleaning (refanger) for obfuscated IOCs.
Handles: hxxp, h-t-t-p, [.], [at], {.}, 0xIP, IPv6[], ftp[:], HTML-like, control chars, etc.
"""
from __future__ import annotations

import re


def refanger(value: str | None) -> tuple[str | None, bool]:
    """
    Advanced input cleaning (Refanger) - cleans common IOC obfuscation patterns.
    Returns: (cleaned_value, was_changed)
    """
    if not value:
        return value, False

    original = value
    cleaned = value

    # --- Protocol: hyphen-defanged (h-t-t-p, h-t-t-p-s) -> http(s)
    cleaned = re.sub(r'h\-t\-t\-p\-s', 'https', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'h\-t\-t\-p(?!\-s)', 'http', cleaned, flags=re.IGNORECASE)
    # --- Protocol: hxxp, h**p
    cleaned = re.sub(r'hxxp[s]?', lambda m: 'http' + ('s' if 's' in m.group(0) else ''), cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'h\*\*p[s]?', lambda m: 'http' + ('s' if 's' in m.group(0) else ''), cleaned, flags=re.IGNORECASE)
    # --- Typo: htp:// -> http://
    cleaned = re.sub(r'\bhtp://', 'http://', cleaned, flags=re.IGNORECASE)
    # --- Bracket-defanged protocol: http[:][/][/], ftp[:][/][/], sftp[:][/][/]
    cleaned = re.sub(r'\[\s*:\s*\]', ':', cleaned)
    cleaned = re.sub(r'\[\s*/\s*\]', '/', cleaned)
    # --- ftp/sftp so ftp[:]// -> ftp:// ([:] already -> : above, need // from [/][/])
    cleaned = re.sub(r'\bftp:\s*//', 'ftp://', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\bsftp:\s*//', 'sftp://', cleaned, flags=re.IGNORECASE)
    # --- Backslash instead of slash: https\\91.210 -> https://91.210
    cleaned = re.sub(r'(https?|ftp|sftp):\\\\', lambda m: m.group(1).lower() + '://', cleaned, flags=re.IGNORECASE)

    # --- Email @ defanging: [at], (at), {at}, [@]
    cleaned = re.sub(r'\[\s*at\s*\]', '@', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\(\s*at\s*\)', '@', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\{\s*at\s*\}', '@', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\[\s*@\s*\]', '@', cleaned)

    # --- Dots
    cleaned = re.sub(r'\[\.\]', '.', cleaned)
    cleaned = re.sub(r'\(\.\)', '.', cleaned)
    cleaned = re.sub(r'\[\s*dot\s*\]', '.', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\{\s*\.\s*\}', '.', cleaned)

    # --- IP: hex octets 0x7F.0x00.0x00.0x01 -> 127.0.0.1
    def _hex_ip(m: re.Match) -> str:
        try:
            return '.'.join(str(int(x, 16)) for x in m.groups())
        except (ValueError, TypeError):
            return m.group(0)
    cleaned = re.sub(r'\b0x([0-9A-Fa-f]{1,2})\.0x([0-9A-Fa-f]{1,2})\.0x([0-9A-Fa-f]{1,2})\.0x([0-9A-Fa-f]{1,2})\b', _hex_ip, cleaned)

    # --- IPv6: strip outer brackets [2001:db8:...] -> 2001:db8:...
    cleaned = re.sub(r'\[([0-9A-Fa-f:]{3,})\](?!\w)', r'\1', cleaned)

    # --- Remove null bytes and other control chars (\x00, \x01, etc.)
    cleaned = re.sub(r'\\x[0-9A-Fa-f]{2}', '', cleaned)
    cleaned = ''.join(c for c in cleaned if ord(c) >= 32 or c in '\t\n\r')

    # --- Remove whitespace inside IPs (e.g., "1. 1. 1. 1" -> "1.1.1.1")
    ip_pattern = r'(\d+)\s*\.\s*(\d+)\s*\.\s*(\d+)\s*\.\s*(\d+)'
    cleaned = re.sub(ip_pattern, r'\1.\2.\3.\4', cleaned)

    # Strip common prefixes like "ip: " or "IP: "
    cleaned = re.sub(r'^(ip|IP|Ip):\s*', '', cleaned)

    was_changed = cleaned != original
    return cleaned.strip(), was_changed


def sanitize_comment(comment: str | None) -> str:
    """Remove newlines and excessive whitespace from comments."""
    if not comment:
        return ''
    sanitized = re.sub(r'[\r\n]+', ' ', comment)
    sanitized = re.sub(r'\s+', ' ', sanitized)
    return sanitized.strip()
