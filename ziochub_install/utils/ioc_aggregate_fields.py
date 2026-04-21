"""
Compute country_code, tld, email_domain for IOC rows (Live Stats aggregates).

Used by MISP sync and by backfill so that Top Countries, Top TLDs, Top Email Domains
show data for imported IOCs. No DB queries here; rare_find_type is computed elsewhere in app.
"""
from __future__ import annotations

from urllib.parse import urlparse


def compute_ioc_aggregate_fields(
    ioc_type: str,
    value: str,
    geoip_reader=None,
) -> dict:
    """
    Compute country_code (IP), tld (Domain/URL), email_domain (Email) for an IOC.

    :param ioc_type: One of IP, Domain, URL, Email (Hash is ignored).
    :param value: The IOC value string.
    :param geoip_reader: Optional geoip2.database.Reader for IP lookup; if None, country_code is None.
    :return: Dict with keys country_code, tld, email_domain (only relevant one set per type).
    """
    out = {'country_code': None, 'tld': None, 'email_domain': None}
    val = (value or '').strip()
    if not val:
        return out

    if ioc_type == 'IP':
        if geoip_reader:
            try:
                response = geoip_reader.city(val)
                cc = response.country.iso_code
                if cc:
                    out['country_code'] = cc.lower()
            except Exception:
                pass

    elif ioc_type == 'Domain':
        if '.' in val:
            tld = val.split('.')[-1].lower()
            if tld and len(tld) <= 30:
                out['tld'] = tld

    elif ioc_type == 'URL':
        try:
            host = urlparse(val).hostname
            if host and '.' in host:
                tld = host.split('.')[-1].lower()
                if tld and len(tld) <= 30:
                    out['tld'] = tld
        except Exception:
            pass

    elif ioc_type == 'Email':
        if '@' in val:
            domain = val.split('@')[-1].lower()
            if domain and len(domain) <= 250:
                out['email_domain'] = domain

    return out
