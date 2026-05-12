#!/usr/bin/env python3
"""
Query ZIoCHub for the STIX 2.1 Indicator (same shape as TAXII) for a given IOC type+value.

Requires a normal user session (form login). Environment variables (optional defaults in argparse):

  ZIOCHUB_BASE_URL   e.g. https://ziochub.example.com:5000
  ZIOCHUB_USERNAME
  ZIOCHUB_PASSWORD

Usage:
  python scripts/stix_taxii_lookup.py --type Domain --value evil.example.com
  python scripts/stix_taxii_lookup.py --type IP --value 203.0.113.1 --fetch-taxii

--fetch-taxii performs an extra unauthenticated GET to the public TAXII object URL
(same as FireEye would see if feeds are public) and prints the response status + JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def _die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def main() -> None:
    p = argparse.ArgumentParser(description='ZIoCHub STIX/TAXII IOC lookup (authenticated).')
    p.add_argument('--base-url', default=os.environ.get('ZIOCHUB_BASE_URL', '').rstrip('/'),
                   help='Server root URL (or set ZIOCHUB_BASE_URL)')
    p.add_argument('--user', '-u', default=os.environ.get('ZIOCHUB_USERNAME', ''),
                   help='Username (or ZIOCHUB_USERNAME)')
    p.add_argument('--password', '-p', default=os.environ.get('ZIOCHUB_PASSWORD', ''),
                   help='Password (or ZIOCHUB_PASSWORD)')
    p.add_argument('--type', '-t', required=True, help='IOC type: IP, Domain, URL, Hash, Email')
    p.add_argument('--value', '-v', required=True, help='IOC value')
    p.add_argument('--fetch-taxii', action='store_true',
                   help='Also GET the TAXII object URL (no session cookie); needs public feeds enabled')
    args = p.parse_args()

    if not args.base_url:
        _die('Missing --base-url or ZIOCHUB_BASE_URL')
    if not args.user or not args.password:
        _die('Missing credentials: use --user/--password or ZIOCHUB_USERNAME / ZIOCHUB_PASSWORD')

    try:
        import requests
    except ImportError:
        _die('Install requests: pip install requests', 2)

    s = requests.Session()
    s.headers.setdefault('User-Agent', 'ziochub-stix-taxii-lookup/1.0')

    login_url = f'{args.base_url}/login'
    r = s.post(
        login_url,
        data={'username': args.user, 'password': args.password},
        allow_redirects=True,
        timeout=60,
    )
    if r.status_code != 200:
        _die(f'Login HTTP {r.status_code}: {r.text[:500]}')
    if '/login' in (r.url or '') and 'change-password' not in (r.url or ''):
        _die('Login appears to have failed (still on login page). Check user/password or forced password change.')

    lookup_url = f'{args.base_url}/api/stix-ioc-lookup'
    r2 = s.get(
        lookup_url,
        params={'type': args.type.strip(), 'value': args.value.strip()},
        headers={'Accept': 'application/json'},
        timeout=60,
    )
    print(f'GET {r2.url} -> HTTP {r2.status_code}')
    try:
        data = r2.json()
    except Exception:
        _die(r2.text[:2000])
    print(json.dumps(data, ensure_ascii=False, indent=2))

    if not data.get('success'):
        raise SystemExit(3)

    if args.fetch_taxii and data.get('found') and data.get('urls', {}).get('taxii_get_object'):
        taxii_url = data['urls']['taxii_get_object']
        accept = (data.get('taxii_request_hint') or {}).get('Accept') or 'application/taxii+json;version=2.1'
        r3 = requests.get(
            taxii_url,
            headers={'Accept': accept},
            timeout=60,
        )
        print('\n--- TAXII GET object (unauthenticated) ---')
        print(f'GET {taxii_url} -> HTTP {r3.status_code}')
        try:
            print(json.dumps(r3.json(), ensure_ascii=False, indent=2))
        except Exception:
            print(r3.text[:4000])


if __name__ == '__main__':
    main()
