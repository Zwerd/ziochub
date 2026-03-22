"""
Allowlist loading and checking. Pass allowlist file path to avoid app dependency.
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse


def load_allowlist(allowlist_file: str | None) -> list[str]:
    """Load allowlist entries from file."""
    allowlist: list[str] = []
    if allowlist_file:
        try:
            with open(allowlist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        allowlist.append(line)
        except OSError as e:
            print(f"Error loading allowlist: {e}")
    return allowlist


_CACHE: dict[str, dict] = {}


def clear_allowlist_cache(allowlist_file: str | None = None) -> None:
    """Clear parsed allowlist cache (all files or a specific file)."""
    global _CACHE
    if allowlist_file:
        _CACHE.pop(allowlist_file, None)
    else:
        _CACHE = {}


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _extract_host(value: str, ioc_type: str) -> str:
    """Extract host/domain for Domain/URL allowlist checks."""
    v = (value or '').strip()
    if not v:
        return ''
    if ioc_type == 'URL':
        # urlparse requires scheme to reliably populate netloc
        parsed = urlparse(v if '://' in v else ('http://' + v))
        host = (parsed.hostname or '').strip()
        return host.lower().strip('.')
    return v.lower().strip('.')


def _parse_allowlist_entries(allowlist_file: str | None) -> dict:
    """
    Parse allowlist into structured sets.

    Supported line formats (backwards compatible):
      - <ip>                   (exact IP)
      - <cidr>                 (CIDR, e.g. 10.0.0.0/8)
      - <domain>               (treated as suffix match: domain + subdomains)
      - domain:<domain>        (exact domain match only)
      - suffix:<domain>        (suffix match: domain + subdomains)
      - tld:<tld>              (TLD match, without dot)
      - ip:<ip> / cidr:<cidr>  (explicit)
    """
    if not allowlist_file:
        return {
            'mtime': None,
            'raw': '',
            'ips': set(),
            'cidrs': [],
            'domains_exact': set(),
            'domains_suffix': set(),
            'tlds': set(),
        }

    try:
        mtime = os.path.getmtime(allowlist_file)
    except OSError:
        mtime = None

    cached = _CACHE.get(allowlist_file)
    if cached and cached.get('mtime') == mtime:
        return cached

    raw = ''
    try:
        with open(allowlist_file, 'r', encoding='utf-8', errors='replace') as f:
            raw = f.read()
    except OSError:
        raw = ''

    ips: set[str] = set()
    cidrs: list[ipaddress._BaseNetwork] = []
    domains_exact: set[str] = set()
    domains_suffix: set[str] = set()
    tlds: set[str] = set()

    for line in raw.splitlines():
        line = (line or '').strip()
        if not line or line.startswith('#'):
            continue
        kind = None
        val = line
        if ':' in line:
            k, rest = line.split(':', 1)
            k = k.strip().lower()
            if k in {'domain', 'suffix', 'tld', 'ip', 'cidr'}:
                kind = k
                val = rest.strip()

        if not val:
            continue

        if kind in {'cidr'} or (kind is None and '/' in val):
            try:
                cidrs.append(ipaddress.ip_network(val, strict=False))
                continue
            except ValueError:
                pass

        if kind in {'ip'} or (kind is None and _looks_like_ip(val)):
            ips.add(val.strip())
            continue

        if kind == 'tld':
            tlds.add(val.strip().lstrip('.').lower())
            continue

        if kind == 'domain':
            domains_exact.add(val.strip().lower().strip('.'))
            continue

        # Default for domains: treat as suffix match (safer than substring).
        domains_suffix.add(val.strip().lower().strip('.'))

    parsed = {
        'mtime': mtime,
        'raw': raw,
        'ips': ips,
        'cidrs': cidrs,
        'domains_exact': domains_exact,
        'domains_suffix': domains_suffix,
        'tlds': tlds,
    }
    _CACHE[allowlist_file] = parsed
    return parsed


def check_allowlist(
    value: str, ioc_type: str, allowlist_file: str | None
) -> tuple[bool, str | None]:
    """
    Check if an IOC is in the allowlist (Safety Net).
    Returns: (is_blocked, reason)
    """
    if ioc_type not in ['IP', 'Domain', 'URL']:
        return False, None

    parsed = _parse_allowlist_entries(allowlist_file)

    if ioc_type == 'IP':
        try:
            ip_obj = ipaddress.ip_address((value or '').strip())
        except ValueError:
            return False, None
        if str(ip_obj) in parsed['ips']:
            return True, f"Matches allowlist IP: {ip_obj}"
        for net in parsed['cidrs']:
            try:
                if ip_obj in net:
                    return True, f"Matches allowlist CIDR: {net}"
            except Exception:
                continue
        return False, None

    host = _extract_host(value, ioc_type)
    if not host:
        return False, None
    if host in parsed['domains_exact']:
        return True, f"Matches allowlist domain: {host}"
    for suffix in parsed['domains_suffix']:
        if host == suffix or host.endswith('.' + suffix):
            return True, f"Matches allowlist suffix: {suffix}"
    tld = host.rsplit('.', 1)[-1] if '.' in host else host
    if tld and tld in parsed['tlds']:
        return True, f"Matches allowlist TLD: {tld}"

    return False, None
