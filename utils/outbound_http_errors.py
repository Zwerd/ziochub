"""
Classify outbound HTTP failures for vendor integrations (WAF, timeout, gateway).
"""
from __future__ import annotations

_WAF_BODY_MARKERS = (
    'access denied',
    'request blocked',
    'request rejected',
    'forbidden',
    'akamai',
    'cloudflare',
    'incapsula',
    'imperva',
    'web application firewall',
    'waf',
    'unauthorized request',
    'security policy',
    'blocked by',
    'not allowed',
)

_GATEWAY_STATUS = frozenset({502, 503, 504})


def _body_suggests_waf(status_code: int, body: str) -> bool:
    if status_code not in (403, 406, 429, 502, 503):
        return False
    blob = (body or '').strip().lower()
    if not blob:
        return status_code in (403, 429)
    if blob.startswith('<!doctype') or blob.startswith('<html'):
        return True
    return any(m in blob for m in _WAF_BODY_MARKERS)


def format_http_response_error(operation: str, status_code: int, body: str = '') -> str:
    """Human-readable error for a non-success HTTP response."""
    op = (operation or 'request').strip()
    snippet = (body or '').strip().replace('\n', ' ')[:160]
    if status_code in _GATEWAY_STATUS:
        label = 'gateway_error'
        if _body_suggests_waf(status_code, body):
            label = 'waf_or_gateway_blocked'
        return f'{op} {label} HTTP {status_code}' + (f': {snippet}' if snippet else '')
    if status_code == 403 and _body_suggests_waf(status_code, body):
        return f'{op} waf_blocked HTTP 403' + (f': {snippet}' if snippet else '')
    if status_code == 429:
        return f'{op} rate_limited HTTP 429' + (f': {snippet}' if snippet else '')
    return f'{op} HTTP {status_code}' + (f': {snippet}' if snippet else '')


def format_requests_exception(operation: str, exc: Exception) -> str:
    """Human-readable error for requests/urllib transport failures."""
    op = (operation or 'request').strip()
    name = type(exc).__name__
    msg = str(exc).strip().replace('\n', ' ')
    low = f'{name} {msg}'.lower()
    if 'timeout' in low or 'timed out' in name.lower():
        return f'{op} timeout ({name})' + (f': {msg[:120]}' if msg else '')
    if 'connectionerror' in name.lower() or 'connection refused' in low:
        return f'{op} connection_error ({name})' + (f': {msg[:120]}' if msg else '')
    if 'ssl' in low or 'certificate' in low:
        return f'{op} tls_error ({name})' + (f': {msg[:120]}' if msg else '')
    return f'{op} network_error ({name})' + (f': {msg[:120]}' if msg else '')
