"""
IOC validation warnings (do not block submission).
Detects private IP, localhost, .local domain, etc.
"""
from __future__ import annotations

import ipaddress


def get_ioc_warnings(value: str, ioc_type: str) -> list[str]:
    """
    Return a list of warning messages for an IOC. Does not block submission.
    """
    warnings = []
    if not value or not value.strip():
        return warnings
    value = value.strip()

    if ioc_type == 'IP':
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:
                warnings.append('Private IP range (RFC 1918)')
            if ip.is_loopback:
                warnings.append('Loopback / localhost')
            if ip.is_link_local:
                warnings.append('Link-local address')
        except ValueError:
            pass

    if ioc_type == 'Domain':
        lower = value.lower()
        if lower.endswith('.local'):
            warnings.append('".local" domain (often internal)')
        if lower in ('localhost', 'localhost.'):
            warnings.append('Localhost hostname')
        if lower.endswith('.internal') or '.internal.' in lower:
            warnings.append('".internal" domain (often internal)')

    return warnings
