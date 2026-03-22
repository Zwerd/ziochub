"""
Decode obfuscated content before IOC extraction: HTML entities, hex byte sequences, hex dump.
Used by all Submit IOCs flows (Single, TXT, CSV, Paste).
"""
from __future__ import annotations

import re
import html


def decode_html_entities(text: str | None) -> str:
    """Decode &#123; &#x7B; &amp; &lt; etc. so IOCs like example&#46;com become example.com."""
    if not text:
        return ''
    # Python html.unescape handles &amp; &lt; &#123; &#x7B; etc.
    return html.unescape(text)


def decode_hex_byte_sequences(text: str | None) -> str:
    """
    Find sequences of hex bytes (space-separated like "68 74 74 70" or continuous "68747470"),
    decode to ASCII, return decoded string to append to scan buffer.
    """
    if not text:
        return ''
    out = []
    # Space-separated hex bytes: 68 74 74 70 3a 2f 2f
    for m in re.finditer(r'(?:\b[0-9A-Fa-f]{2}\s+)+[0-9A-Fa-f]{2}\b', text):
        try:
            decoded = bytes.fromhex(m.group(0).replace(' ', '')).decode('ascii', errors='replace')
            if decoded.isprintable() or '\n' in decoded or '\r' in decoded:
                out.append(decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    # Long continuous hex (e.g. 687474703a2f2f...)
    for m in re.finditer(r'\b[0-9A-Fa-f]{14,}\b', text):
        s = m.group(0)
        try:
            decoded = bytes.fromhex(s).decode('ascii', errors='replace')
            if len(decoded) >= 5 and (decoded.isprintable() or '\n' in decoded):
                out.append(decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    return ' '.join(out) if out else ''


def decode_hex_dump(text: str | None) -> str:
    """
    Parse hex dump lines (e.g. 00000020  68 78 78 70 3a 2f 2f 61 64 76  |hxxp://adv|),
    extract hex bytes, decode to ASCII. Returns decoded string for IOC scanning.
    """
    if not text:
        return ''
    lines = (text or '').splitlines()
    decoded_parts = []
    for line in lines:
        # Format: 00000020  68 78 78 70 3a 2f 2f 61 64 76 2d 63 6f 6e 74  |hxxp://adv-cont|
        # Or: 00000020  68 78 78 70 3a 2f 2f
        stripped = line.strip()
        if not stripped:
            continue
        # Skip if line doesn't look like hex dump (offset + hex bytes)
        if not re.match(r'^[0-9A-Fa-f]{8}\s+', stripped):
            continue
        # Remove offset (first 8 hex chars + spaces)
        rest = re.sub(r'^[0-9A-Fa-f]{8}\s+', '', stripped)
        # Remove ASCII column (|...| at end)
        rest = re.sub(r'\s*\|[^\|]*\|?\s*$', '', rest)
        # Collect hex bytes (groups of 2 hex digits)
        hex_bytes = re.findall(r'[0-9A-Fa-f]{2}', rest)
        if not hex_bytes:
            continue
        try:
            decoded = bytes.fromhex(''.join(hex_bytes)).decode('ascii', errors='replace')
            if decoded.strip():
                decoded_parts.append(decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    return ' '.join(decoded_parts) if decoded_parts else ''


def prepare_text_for_ioc_extraction(text: str | None) -> str:
    """
    Single entry point: decode HTML entities, add decoded hex and hex-dump content,
    so that IOCs inside hex-encoded or hex-dump blocks are found.
    Returns combined string to pass to _refang_text_for_scan + _extract_iocs_from_text (or refanger).
    """
    if not text:
        return ''
    decoded_html = decode_html_entities(text)
    hex_decoded = decode_hex_byte_sequences(text)
    hex_dump_decoded = decode_hex_dump(text)
    combined = decoded_html
    if hex_decoded:
        combined += '\n' + hex_decoded
    if hex_dump_decoded:
        combined += '\n' + hex_dump_decoded
    return combined
