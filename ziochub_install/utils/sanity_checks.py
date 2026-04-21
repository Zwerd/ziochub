"""
Sanity checks for IOC submission - Critical (block) and Warnings (allow with alert).
Critical: TLD-only, Critical infra IPs. (Organization domains / protected assets: use Admin → Allowlist.)
Warnings: Short domain, Hash mismatch, Whitespace, URL with hash,
          Bogon IPs, Popular domains, Cloud providers, Punycode/IDN, DGA-like,
          URL credentials, URL raw IP, Deep subdomains, Free email providers, Stale IOCs.
"""
from __future__ import annotations

import math
import re
import os
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRITICAL_INFRA_IPS = {
    '8.8.8.8', '8.8.4.4',      # Google DNS
    '1.1.1.1', '1.0.0.1',      # Cloudflare DNS
}

_CCSLD_SUFFIXES = {
    'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il', 'idf.il',
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'ac.in', 'gov.in',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
    'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
    'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
    'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw',
    'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
    'co.id', 'or.id', 'go.id', 'ac.id', 'web.id',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
    'co.th', 'or.th', 'go.th', 'ac.th', 'in.th',
    'com.ar', 'net.ar', 'org.ar', 'gov.ar', 'edu.ar',
    'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
    'co.ke', 'or.ke', 'go.ke', 'ac.ke', 'ne.ke',
    'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng',
    'com.eg', 'org.eg', 'gov.eg', 'edu.eg', 'net.eg',
    'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
    'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
}

# Bogon / reserved IP networks NOT already covered by the local_ip
# (RFC 1918 + loopback) or testnet_ip (RFC 5737) checks.
_BOGON_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),       # CGNAT (RFC 6598)
    ipaddress.ip_network('169.254.0.0/16'),      # Link-local
    ipaddress.ip_network('192.0.0.0/24'),        # IETF Protocol Assignments
    ipaddress.ip_network('192.88.99.0/24'),      # 6to4 Relay Anycast
    ipaddress.ip_network('198.18.0.0/15'),       # Benchmarking (RFC 2544)
    ipaddress.ip_network('224.0.0.0/4'),         # Multicast
    ipaddress.ip_network('240.0.0.0/4'),         # Reserved / future use
    ipaddress.ip_network('255.255.255.255/32'),  # Broadcast
]

_POPULAR_DOMAINS = {
    'google.com', 'google.co.il', 'youtube.com', 'facebook.com',
    'amazon.com', 'microsoft.com', 'apple.com', 'x.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'wikipedia.org', 'netflix.com',
    'reddit.com', 'github.com', 'cloudflare.com', 'office.com',
    'live.com', 'bing.com', 'office365.com', 'windows.com',
    'windowsupdate.com', 'outlook.com', 'yahoo.com', 'whatsapp.com',
    'zoom.us', 'adobe.com', 'salesforce.com', 'dropbox.com',
    'slack.com', 'wordpress.com', 'stackoverflow.com', 'mozilla.org',
    'python.org', 'docker.com', 'npmjs.com', 'pypi.org',
    'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    'amazonaws.com', 'azure.com', 'akamai.com', 'fastly.com',
    'cdn77.com', 'telegram.org', 'signal.org', 'tiktok.com',
    'paypal.com', 'github.io', 'gitlab.com',
}

_CLOUD_PROVIDER_SUFFIXES = [
    'amazonaws.com', 'cloudfront.net', 's3.amazonaws.com',
    'azurewebsites.net', 'azure-api.net', 'azureedge.net',
    'blob.core.windows.net', 'trafficmanager.net',
    'googleapis.com', 'googleusercontent.com', 'gstatic.com',
    'googlevideo.com', 'firebaseapp.com', 'appspot.com',
    'akamaiedge.net', 'akamai.net', 'akamaitechnologies.com',
    'fastly.net', 'fastlylb.net',
    'cloudflare.net', 'workers.dev',
    'edgecastcdn.net', 'stackpathdns.com',
    'cdn77.org', 'llnwd.net',
    'incapdns.net', 'impervadns.net',
    'github.io', 'herokuapp.com', 'netlify.app', 'vercel.app',
]

_FREE_EMAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'yahoo.co.il', 'outlook.com',
    'hotmail.com', 'hotmail.co.il', 'aol.com', 'mail.com',
    'protonmail.com', 'proton.me', 'zoho.com',
    'yandex.com', 'yandex.ru', 'icloud.com',
    'live.com', 'msn.com', 'gmx.com', 'gmx.net',
    'tutanota.com', 'fastmail.com', 'mail.ru',
    'walla.co.il', 'walla.com',
}

_STALE_DAYS_THRESHOLD = 180

_URL_CREDS_RE = re.compile(r'://[^/]*:[^/@]+@')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _domain_label(domain: str) -> str | None:
    """Return the registrable domain label, accounting for ccSLDs.
    e.g. 'kohani.co.il' -> 'kohani', 't.co' -> 't', 'example.com' -> 'example'.
    Returns None if the domain has no meaningful label."""
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return None
    suffix = '.'.join(parts[-2:])
    if suffix in _CCSLD_SUFFIXES and len(parts) >= 3:
        return parts[-3]
    return parts[-2]


def _extract_domain(val: str, ioc_type: str) -> str:
    """Extract the bare domain from a Domain or URL value."""
    if ioc_type == 'URL':
        try:
            parsed = urlparse(val if '://' in val else 'http://' + val)
            return (parsed.hostname or '').strip('.').lower()
        except Exception:
            return ''
    return val.lower().strip('.')


def _is_bogon_ip(ip_str: str) -> ipaddress.IPv4Network | None:
    """Return the matching bogon network, or None."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None
    for net in _BOGON_NETWORKS:
        if ip in net:
            return net
    return None


def _is_popular_domain(domain: str) -> str | None:
    """Return the matched popular domain, or None."""
    d = domain.lower().strip('.')
    if d in _POPULAR_DOMAINS:
        return d
    for pop in _POPULAR_DOMAINS:
        if d.endswith('.' + pop):
            return pop
    return None


def _is_cloud_provider(domain: str) -> str | None:
    """Return the matched cloud/CDN suffix, or None."""
    d = domain.lower().strip('.')
    for suffix in _CLOUD_PROVIDER_SUFFIXES:
        if d == suffix or d.endswith('.' + suffix):
            return suffix
    return None


def _is_punycode(domain: str) -> bool:
    """True if any label in the domain uses Punycode (xn-- prefix)."""
    return any(lbl.startswith('xn--') for lbl in domain.lower().split('.'))


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def _is_dga_like(domain: str) -> bool:
    """Heuristic: flag domain labels that look algorithmically generated."""
    label = _domain_label(domain)
    if not label or len(label) < 8:
        return False
    low = label.lower()
    entropy = _shannon_entropy(low)
    vowels = set('aeiou')
    alpha = [c for c in low if c.isalpha()]
    if not alpha:
        return len(label) > 10
    consonant_ratio = sum(1 for c in alpha if c not in vowels) / len(alpha)
    has_digits = any(c.isdigit() for c in low)
    if consonant_ratio == 1.0 and len(alpha) >= 6:
        return True
    if entropy > 3.5 and consonant_ratio > 0.7:
        return True
    if len(label) > 12 and has_digits and entropy > 3.0:
        return True
    return False


def _subdomain_depth(domain: str) -> int:
    """Number of subdomain levels (a.b.c.evil.com -> 3)."""
    parts = domain.lower().strip('.').split('.')
    suffix = '.'.join(parts[-2:])
    if suffix in _CCSLD_SUFFIXES:
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def _url_has_credentials(url: str) -> bool:
    return bool(_URL_CREDS_RE.search(url))


def _url_host_is_ip(url: str) -> str | None:
    """If the URL host is a raw IP address, return it."""
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        host = (parsed.hostname or '').strip()
        if host:
            ipaddress.ip_address(host)
            return host
    except ValueError:
        pass
    return None


def _is_free_email_domain(domain: str) -> bool:
    return domain.lower().strip('.') in _FREE_EMAIL_DOMAINS


# ---------------------------------------------------------------------------
# Critical checks (block submission)
# ---------------------------------------------------------------------------
# Note: Organization domains and other protected assets are defined in
# Admin → Allowlist (hard block, no override). No separate org_domains.txt.


def check_critical(value: str, ioc_type: str, data_dir: str = '') -> tuple[bool, str | None]:
    """
    Critical checks - block submission.
    Returns: (is_blocked, error_message) - if blocked, message explains why.
    """
    if not value:
        return False, None
    val = value.strip()

    # 1. TLD only
    if ioc_type in ('Domain', 'URL'):
        val_lower = val.lower().lstrip('.')
        if re.match(r'^[a-z]{2,6}$', val_lower) or re.match(r'^[a-z]{2}\.[a-z]{2}$', val_lower):
            return True, 'Blocking entire TLD (.com, .ru, etc.) would break the internet. Block specific domains instead.'
        if val.strip().startswith('.') and len(val.strip()) <= 10:
            return True, 'Value appears to be TLD-only. Block specific domains, not entire TLD.'

    # 2. Critical infrastructure IPs
    if ioc_type == 'IP':
        try:
            ipaddress.ip_address(val)
            if val in CRITICAL_INFRA_IPS:
                return True, f'Critical infrastructure IP ({val}) - blocking DNS would break network access.'
        except ValueError:
            pass

    return False, None


# ---------------------------------------------------------------------------
# Submission-time warnings (orange alert, does not block)
# ---------------------------------------------------------------------------


def get_sanity_warnings(value: str, ioc_type: str) -> list[str]:
    """Warning checks - allow submission but show orange alert."""
    warnings: list[str] = []
    if not value:
        return warnings
    val = value.strip()

    # --- existing checks ---

    # Short domain - ccSLD-aware
    if ioc_type == 'Domain':
        label = _domain_label(val)
        parts = val.lower().split('.')
        if label is not None and len(label) <= 2:
            warnings.append(f'Very short domain ({val}). Possible typo or URL shortener.')
        if len(parts) >= 2 and sum(len(p) for p in parts) < 6:
            warnings.append(f'Very short domain ({val}). High risk of blocking legitimate sites.')

    # Hash type mismatch
    if ioc_type == 'Hash' and re.match(r'^[a-fA-F0-9]+$', val):
        n = len(val)
        if n not in (32, 40, 64):
            warnings.append(f'Hash length {n} - MD5=32, SHA1=40, SHA256=64. Verify type.')

    # Whitespace padding
    if value != val:
        warnings.append('Leading/trailing whitespace was trimmed.')

    # URL containing hash-like string
    if ioc_type == 'URL':
        for pattern, name in [
            (r'[a-fA-F0-9]{64}', 'SHA-256'),
            (r'[a-fA-F0-9]{40}', 'SHA1'),
            (r'[a-fA-F0-9]{32}', 'MD5'),
        ]:
            m = re.search(pattern, val)
            if m:
                snippet = m.group(0)[:4] + '...' if len(m.group(0)) >= 8 else m.group(0)
                warnings.append(f'URL contains {name}-like hash ({snippet}). Verify this is correct.')
                break

    # --- new checks ---

    # Bogon / reserved IP
    if ioc_type == 'IP':
        net = _is_bogon_ip(val)
        if net:
            warnings.append(f'Bogon/reserved IP range ({net}). Not routable on the public internet.')

    # Domain / URL surface checks
    if ioc_type in ('Domain', 'URL'):
        domain = _extract_domain(val, ioc_type)
        if domain:
            pop = _is_popular_domain(domain)
            if pop:
                warnings.append(f'High-traffic domain ({pop}). Blocking could disrupt critical services.')
            else:
                cloud = _is_cloud_provider(domain)
                if cloud:
                    warnings.append(f'Cloud/CDN infrastructure ({cloud}). Blocking may affect many legitimate services.')

            if ioc_type == 'Domain' and _is_free_email_domain(domain):
                warnings.append(f'Free email provider ({domain}). Blocking would cut email access for many users.')

    if ioc_type == 'Domain':
        if _is_punycode(val):
            warnings.append('Punycode/IDN domain detected. May be a homograph phishing attack - verify visually.')
        elif _is_dga_like(val):
            warnings.append('Domain label has DGA-like characteristics (high entropy). Possibly auto-generated.')

        depth = _subdomain_depth(val)
        if depth >= 4:
            warnings.append(f'Excessive subdomain depth ({depth} levels). May indicate DNS tunneling or C2.')

    if ioc_type == 'URL':
        if _url_has_credentials(val):
            warnings.append('URL contains embedded credentials (user:pass@). Security risk in feed data.')
        ip_host = _url_host_is_ip(val)
        if ip_host:
            warnings.append(f'URL uses raw IP ({ip_host}) instead of domain. Common in C2/malware infrastructure.')

    return warnings


# ---------------------------------------------------------------------------
# Feed Pulse anomalies (dashboard scan of all active IOCs)
# ---------------------------------------------------------------------------


def get_feed_pulse_anomalies(items: list[dict]) -> list[dict]:
    """
    Anomaly detection for Feed Pulse - runs on IOC list.
    Returns list of {type, value, message, ioc_type} for exclusion matching.
    """
    anomalies: list[dict] = []
    seen: set[str] = set()
    now = datetime.now()

    for item in items:
        val = (item.get('value') or '').strip()
        ioc_type = item.get('type') or ''
        key = f"{ioc_type}:{val}"
        if key in seen:
            continue
        seen.add(key)

        # ── URL with hash ──
        if ioc_type == 'URL':
            for pattern, name in [
                (r'[a-fA-F0-9]{64}', 'SHA-256'),
                (r'[a-fA-F0-9]{40}', 'SHA1'),
                (r'[a-fA-F0-9]{32}', 'MD5'),
            ]:
                m = re.search(pattern, val)
                if m:
                    full_display = val if len(val) <= 200 else val[:200] + '...'
                    anomalies.append({
                        'type': 'url_contains_hash',
                        'value': val,
                        'message': f'URL contains {name}-like hash. Full value: {full_display}',
                        'ioc_type': ioc_type
                    })
                    break

        # ── IP address checks ──
        if ioc_type == 'IP':
            parts = val.split('.')
            if len(parts) == 4:
                try:
                    a, b, c = int(parts[0]), int(parts[1]), int(parts[2])
                    is_private = (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 127)
                    is_testnet = (
                        (a == 192 and b == 0 and c == 2) or
                        (a == 198 and b == 51 and c == 100) or
                        (a == 203 and b == 0 and c == 113)
                    )
                    if is_private:
                        anomalies.append({
                            'type': 'local_ip',
                            'value': val,
                            'message': f'Detected a Local IP ({val}). Blocking this might cut internal access.',
                            'ioc_type': ioc_type
                        })
                    elif is_testnet:
                        anomalies.append({
                            'type': 'testnet_ip',
                            'value': val,
                            'message': f'Detected TEST-NET address ({val}) - RFC 5737 documentation range. Verify this is not an example.',
                            'ioc_type': ioc_type
                        })
                    else:
                        net = _is_bogon_ip(val)
                        if net:
                            anomalies.append({
                                'type': 'bogon_ip',
                                'value': val,
                                'message': f'Bogon/reserved IP range ({net}). Not routable on the public internet.',
                                'ioc_type': ioc_type
                            })
                except (ValueError, IndexError):
                    pass

        # ── Short domain - ccSLD-aware ──
        if ioc_type == 'Domain':
            label = _domain_label(val)
            if label is not None and len(label) <= 2:
                anomalies.append({
                    'type': 'short_domain',
                    'value': val,
                    'message': f'Detected a very short domain ({val}). Possible typo?',
                    'ioc_type': ioc_type
                })

        # ── Hash type mismatch ──
        if ioc_type == 'Hash' and re.match(r'^[a-fA-F0-9]+$', val):
            n = len(val)
            if n not in (32, 40, 64):
                anomalies.append({
                    'type': 'hash_mismatch',
                    'value': val,
                    'message': f'Hash length {n} - MD5=32, SHA1=40, SHA256=64. Verify type.',
                    'ioc_type': ioc_type
                })

        # ── Defanged ──
        if re.search(r'hxxp|hXXp|h\*\*p|\[\.\]|\(\.\)|\[dot\]', val, re.I):
            anomalies.append({
                'type': 'defanged',
                'value': val,
                'message': f'Defanged URL/domain ({val[:30]}...). Firewall needs http and normal dots.',
                'ioc_type': item.get('type') or ''
            })

        # ── TLD only ──
        if ioc_type in ('Domain', 'URL') and val.startswith('.') and len(val) <= 10:
            anomalies.append({
                'type': 'tld_only',
                'value': val,
                'message': f'TLD-only ({val}). Blocking entire TLD would break the internet.',
                'ioc_type': ioc_type
            })

        # ── Critical infra IP ──
        if ioc_type == 'IP' and val in CRITICAL_INFRA_IPS:
            anomalies.append({
                'type': 'critical_infra',
                'value': val,
                'message': f'Critical infrastructure IP ({val}). Blocking would break DNS.',
                'ioc_type': ioc_type
            })

        # ── NEW: Popular / high-traffic domain ──
        if ioc_type in ('Domain', 'URL'):
            domain = _extract_domain(val, ioc_type)
            if domain:
                pop = _is_popular_domain(domain)
                if pop:
                    anomalies.append({
                        'type': 'popular_domain',
                        'value': val,
                        'message': f'High-traffic domain ({pop}). Blocking could disrupt critical services for the entire organization.',
                        'ioc_type': ioc_type
                    })
                else:
                    # Cloud / CDN provider (skip if already flagged as popular)
                    cloud = _is_cloud_provider(domain)
                    if cloud:
                        anomalies.append({
                            'type': 'cloud_provider',
                            'value': val,
                            'message': f'Cloud/CDN shared infrastructure ({cloud}). Blocking may affect many legitimate services.',
                            'ioc_type': ioc_type
                        })

                # Free email provider
                if ioc_type == 'Domain' and _is_free_email_domain(domain):
                    anomalies.append({
                        'type': 'free_email_provider',
                        'value': val,
                        'message': f'Free email provider ({domain}). Blocking would cut email access for many users.',
                        'ioc_type': ioc_type
                    })

        # ── NEW: Punycode / IDN domain ──
        if ioc_type == 'Domain' and _is_punycode(val):
            anomalies.append({
                'type': 'punycode_domain',
                'value': val,
                'message': f'Punycode/IDN domain ({val}). May be a homograph phishing attack - verify the rendered characters visually.',
                'ioc_type': ioc_type
            })

        # ── NEW: DGA-like domain (skip if already punycode) ──
        if ioc_type == 'Domain' and not _is_punycode(val) and _is_dga_like(val):
            anomalies.append({
                'type': 'dga_suspect',
                'value': val,
                'message': f'Domain label has DGA-like characteristics - high entropy, unusual character distribution ({val}). Possibly auto-generated by malware.',
                'ioc_type': ioc_type
            })

        # ── NEW: Excessive subdomain depth ──
        if ioc_type == 'Domain':
            depth = _subdomain_depth(val)
            if depth >= 4:
                anomalies.append({
                    'type': 'deep_subdomain',
                    'value': val,
                    'message': f'Excessive subdomain depth ({depth} levels). May indicate DNS tunneling, DGA, or C2 beaconing.',
                    'ioc_type': ioc_type
                })

        # ── NEW: URL with embedded credentials ──
        if ioc_type == 'URL' and _url_has_credentials(val):
            anomalies.append({
                'type': 'url_credentials',
                'value': val,
                'message': 'URL contains embedded credentials (user:password@host). Security risk - credentials exposed in feed data.',
                'ioc_type': ioc_type
            })

        # ── NEW: URL with raw IP as host ──
        if ioc_type == 'URL':
            ip_host = _url_host_is_ip(val)
            if ip_host:
                anomalies.append({
                    'type': 'url_raw_ip',
                    'value': val,
                    'message': f'URL uses raw IP ({ip_host}) instead of domain name. Common pattern in C2 and malware delivery infrastructure.',
                    'ioc_type': ioc_type
                })

        # ── NEW: Stale IOC (permanent, older than threshold) ──
        created_str = item.get('created_at') or ''
        expiration = item.get('expiration') or ''
        if created_str and expiration == 'Permanent':
            try:
                created = datetime.fromisoformat(created_str)
                age_days = (now - created).days
                if age_days > _STALE_DAYS_THRESHOLD:
                    anomalies.append({
                        'type': 'stale_ioc',
                        'value': val,
                        'message': f'Permanent IOC active for {age_days} days. Threat infrastructure rotates - consider reviewing or setting an expiration.',
                        'ioc_type': ioc_type
                    })
            except (ValueError, TypeError):
                pass

    return anomalies
