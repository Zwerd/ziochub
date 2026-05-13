#!/usr/bin/env python3
"""
Query ZIoCHub for the STIX 2.1 Indicator (same shape as TAXII) for a given IOC type+value.

Requires a normal user session (form login). Environment variables (optional defaults in argparse):

  ZIOCHUB_BASE_URL   e.g. https://ziochub.example.com:5000
  ZIOCHUB_USERNAME
  ZIOCHUB_PASSWORD

Usage:
  python scripts/stix_taxii_lookup.py --type Domain --value evil.example.com
  python scripts/stix_taxii_lookup.py -k --base-url https://host:5000 -u USER -p PASS -t IP -v 203.0.113.1
  python scripts/stix_taxii_lookup.py --type IP --value 203.0.113.1 --fetch-taxii

  -k / --insecure  Skip TLS certificate verification (needed for ZIoCHub default self-signed cert).

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
    p.add_argument('--insecure', '-k', action='store_true',
                   help='Skip TLS certificate verification (use with ZIoCHub self-signed HTTPS)')
    args = p.parse_args()

    base_url = (args.base_url or '').rstrip('/')
    verify_tls = not args.insecure
    if verify_tls and os.environ.get('ZIOCHUB_SSL_VERIFY', '').strip().lower() in ('0', 'false', 'no'):
        verify_tls = False

    if not base_url:
        _die('Missing --base-url or ZIOCHUB_BASE_URL')
    if not args.user or not args.password:
        _die('Missing credentials: use --user/--password or ZIOCHUB_USERNAME / ZIOCHUB_PASSWORD')

    try:
        import requests
    except ImportError:
        _die('Install requests: pip install requests', 2)

    s = requests.Session()
    s.headers.setdefault('User-Agent', 'ziochub-stix-taxii-lookup/1.0')
    s.verify = verify_tls
    if not verify_tls:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    login_url = f'{base_url}/login'
    r = s.post(
        login_url,
        data={'username': args.user, 'password': args.password},
        allow_redirects=True,
        timeout=60,
    )
    if r.status_code == 401:
        _die(
            'Login failed (HTTP 401): invalid username or password.\n'
            'STIX is returned only after a successful login ( /api/stix-ioc-lookup requires a session ).\n'
            'Verify the same credentials in the browser; user name is matched case-insensitively.'
        )
    if r.status_code != 200:
        body = (r.text or '')[:500].replace('\n', ' ')
        _die(f'Login HTTP {r.status_code}. Response body (truncated): {body}')
    if '/login' in (r.url or '') and 'change-password' not in (r.url or ''):
        _die(
            'Login appears to have failed (still on /login). Check user/password.\n'
            'STIX output requires an authenticated session.'
        )

    lookup_url = f'{base_url}/api/stix-ioc-lookup'
    r2 = s.get(
        lookup_url,
        params={'type': args.type.strip(), 'value': args.value.strip()},
        headers={'Accept': 'application/json'},
        timeout=60,
    )
    print(f'GET {r2.url} -> HTTP {r2.status_code}')
    if r2.status_code == 404:
        _die(
            'HTTP 404: this server does not expose /api/stix-ioc-lookup (route missing).\n'
            'The STIX lookup API was added in newer ZIoCHub sources (routes/search.py).\n'
            'Fix: copy updated app code to the server (at least routes/search.py), then:\n'
            '     sudo systemctl restart ziochub\n'
            'If you use /opt/ziochub from setup.sh, run an upgrade from a fresh installer ZIP or sync files there.'
        )
    if r2.status_code == 403:
        try:
            err = r2.json()
        except Exception:
            err = {}
        if err.get('require_password_change'):
            _die(
                'API returned 403: this user must change password before using the app (and this script).\n'
                'Log in once in the browser, complete password change, then retry.'
            )
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
            verify=verify_tls,
        )
        print('\n--- TAXII GET object (unauthenticated) ---')
        print(f'GET {taxii_url} -> HTTP {r3.status_code}')
        try:
            print(json.dumps(r3.json(), ensure_ascii=False, indent=2))
        except Exception:
            print(r3.text[:4000])


if __name__ == '__main__':
    main()
