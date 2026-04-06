"""
Allowlist loading and checking. Pass allowlist file path to avoid app dependency.
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse


def _strip_allowlist_inline_comment(s: str) -> str:
    """Strip trailing # comment (same rule as parser; avoids IPs becoming bogus domain suffixes)."""
    return (s or '').split('#', 1)[0].strip()


def _normalize_allowlist_ip_token(val: str) -> str | None:
    """
    Canonical IP string for allowlist storage/lookup, or None.
    Accepts IPv4 with optional :port (host must be IPv4; port digits only).
    """
    v = (val or '').strip()
    if not v:
        return None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if v.count(':') == 1:
        host, port = v.split(':', 1)
        if port.isdigit():
            try:
                return str(ipaddress.ip_address(host.strip()))
            except ValueError:
                return None
    return None


def load_allowlist(allowlist_file: str | None) -> list[str]:
    """Load allowlist entries from file."""
    allowlist: list[str] = []
    if allowlist_file:
        try:
            with open(allowlist_file, 'r', encoding='utf-8-sig') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    line = _strip_allowlist_inline_comment(line)
                    if line:
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
      - Trailing # comments (e.g. "10.0.0.1  # internal") — text after # is ignored
      - IPv4 with port: 10.0.0.1:443 (same as 10.0.0.1 for IP checks)
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
            'ip_sources': {},
            'cidr_sources': [],
            'domain_exact_sources': {},
            'domain_suffix_sources': {},
            'tld_sources': {},
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
        with open(allowlist_file, 'r', encoding='utf-8-sig', errors='replace') as f:
            raw = f.read()
    except OSError:
        raw = ''

    ips: set[str] = set()
    cidrs: list[ipaddress._BaseNetwork] = []
    domains_exact: set[str] = set()
    domains_suffix: set[str] = set()
    tlds: set[str] = set()
    ip_sources: dict[str, str] = {}
    cidr_sources: list[str] = []
    domain_exact_sources: dict[str, str] = {}
    domain_suffix_sources: dict[str, str] = {}
    tld_sources: dict[str, str] = {}

    for raw_line in raw.splitlines():
        display = (raw_line or '').strip()
        if not display or display.startswith('#'):
            continue
        line = _strip_allowlist_inline_comment(display)
        if not line:
            continue
        kind = None
        val = line
        if ':' in line:
            k, rest = line.split(':', 1)
            k = k.strip().lower()
            if k in {'domain', 'suffix', 'tld', 'ip', 'cidr'}:
                kind = k
                val = _strip_allowlist_inline_comment(rest)

        if not val:
            continue

        if kind in {'cidr'} or (kind is None and '/' in val):
            try:
                net = ipaddress.ip_network(val, strict=False)
                cidrs.append(net)
                cidr_sources.append(display)
                continue
            except ValueError:
                pass

        ip_norm = _normalize_allowlist_ip_token(val)
        if kind == 'ip':
            if ip_norm:
                ips.add(ip_norm)
                ip_sources.setdefault(ip_norm, display)
            continue

        if kind is None and ip_norm:
            ips.add(ip_norm)
            ip_sources.setdefault(ip_norm, display)
            continue

        if kind == 'tld':
            t = val.strip().lstrip('.').lower()
            tlds.add(t)
            tld_sources.setdefault(t, display)
            continue

        if kind == 'domain':
            d = val.strip().lower().strip('.')
            domains_exact.add(d)
            domain_exact_sources.setdefault(d, display)
            continue

        # Default for domains: treat as suffix match (safer than substring).
        sfx = val.strip().lower().strip('.')
        domains_suffix.add(sfx)
        domain_suffix_sources.setdefault(sfx, display)

    parsed = {
        'mtime': mtime,
        'raw': raw,
        'ips': ips,
        'cidrs': cidrs,
        'domains_exact': domains_exact,
        'domains_suffix': domains_suffix,
        'tlds': tlds,
        'ip_sources': ip_sources,
        'cidr_sources': cidr_sources,
        'domain_exact_sources': domain_exact_sources,
        'domain_suffix_sources': domain_suffix_sources,
        'tld_sources': tld_sources,
    }
    _CACHE[allowlist_file] = parsed
    return parsed


def _reason_with_source(base: str, source_line: str | None) -> str:
    """Append full allowlist file line (including text after #) for analyst-visible messages."""
    if not source_line:
        return base
    return f"{base} | Allowlist entry: {source_line}"


def check_allowlist(
    value: str, ioc_type: str, allowlist_file: str | None
) -> tuple[bool, str | None]:
    """
    Check if an IOC is in the allowlist (Safety Net).
    Returns: (is_blocked, reason) — reason includes matching file line when available (with # comment).
    """
    if ioc_type not in ['IP', 'Domain', 'URL']:
        return False, None

    parsed = _parse_allowlist_entries(allowlist_file)

    if ioc_type == 'IP':
        try:
            ip_obj = ipaddress.ip_address((value or '').strip())
        except ValueError:
            return False, None
        ip_key = str(ip_obj)
        if ip_key in parsed['ips']:
            src = (parsed.get('ip_sources') or {}).get(ip_key)
            return True, _reason_with_source(f"Matches allowlist IP: {ip_obj}", src)
        cidr_src_list = parsed.get('cidr_sources') or []
        for i, net in enumerate(parsed['cidrs']):
            try:
                if ip_obj in net:
                    src = cidr_src_list[i] if i < len(cidr_src_list) else None
                    return True, _reason_with_source(f"Matches allowlist CIDR: {net}", src)
            except Exception:
                continue
        return False, None

    host = _extract_host(value, ioc_type)
    if not host:
        return False, None
    if host in parsed['domains_exact']:
        src = (parsed.get('domain_exact_sources') or {}).get(host)
        return True, _reason_with_source(f"Matches allowlist domain: {host}", src)
    for suffix in parsed['domains_suffix']:
        if host == suffix or host.endswith('.' + suffix):
            src = (parsed.get('domain_suffix_sources') or {}).get(suffix)
            return True, _reason_with_source(f"Matches allowlist suffix: {suffix}", src)
    tld = host.rsplit('.', 1)[-1] if '.' in host else host
    if tld and tld in parsed['tlds']:
        src = (parsed.get('tld_sources') or {}).get(tld)
        return True, _reason_with_source(f"Matches allowlist TLD: {tld}", src)

    return False, None
