#!/usr/bin/env python3
"""
Query ZIoCHub for the STIX 2.1 Indicator (same shape as TAXII) for a given IOC type+value.

Requires a normal user session (form login). Environment variables (optional defaults in argparse):

  ZIOCHUB_BASE_URL   e.g. https://ziochub.example.com:5000
  ZIOCHUB_USERNAME
  ZIOCHUB_PASSWORD   optional; if unset and you omit --password on the CLI, the script prompts (no echo, not in shell history)

Usage:
  python scripts/stix_taxii_lookup.py --type Domain --value evil.example.com
  cd scripts && python3 stix_taxii_lookup.py --type Domain --value evil.example.com
  python scripts/stix_taxii_lookup.py -k --base-url https://host:5000 -u USER --type IP --value 203.0.113.1
    (password: prompted if ZIOCHUB_PASSWORD is unset — do not pass passwords on the command line)
  python scripts/stix_taxii_lookup.py --type IP --value 203.0.113.1 --fetch-taxii

  -k / --insecure  Skip TLS certificate verification (needed for ZIoCHub default self-signed cert).

--fetch-taxii performs an extra unauthenticated GET to the public TAXII object URL
(same as FireEye would see if feeds are public) and prints the response status + JSON.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_PASSWORD_ARG_UNSET = object()


def _die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def main() -> None:
    _epilog = """
Examples:
  %(prog)s --base-url https://ziochub.example.com:5000 -u analyst -t Domain -v evil.example.com
      (password from ZIOCHUB_PASSWORD or interactive prompt)

  %(prog)s -k --base-url https://host:5000 -u analyst -t IP -v 203.0.113.1
      (-k skips TLS verification; common with self-signed certs)

  %(prog)s -t Hash -v d41d8cd98f00b204e9800998ecf8427e --fetch-taxii
      (also GET the public TAXII object URL when the API returns one)
"""
    p = argparse.ArgumentParser(
        description='ZIoCHub STIX/TAXII IOC lookup (authenticated).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog,
    )
    p.add_argument('--base-url', default=os.environ.get('ZIOCHUB_BASE_URL', '').rstrip('/'),
                   help='Server root URL (or set ZIOCHUB_BASE_URL)')
    p.add_argument('--user', '-u', default=os.environ.get('ZIOCHUB_USERNAME', ''),
                   help='Username (or ZIOCHUB_USERNAME)')
    p.add_argument(
        '--password',
        nargs='?',
        default=_PASSWORD_ARG_UNSET,
        const=None,
        metavar='VALUE',
        help='Password. Prefer omitting this flag: uses ZIOCHUB_PASSWORD or secure prompt (no echo). '
             'Passing a value here is insecure (may appear in shell history). '
             '`--password` alone forces a prompt even if ZIOCHUB_PASSWORD is set.',
    )
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
    if not args.user:
        _die('Missing username: use --user or ZIOCHUB_USERNAME')

    if args.password is _PASSWORD_ARG_UNSET:
        password = (os.environ.get('ZIOCHUB_PASSWORD') or '').strip()
        if not password:
            try:
                password = getpass.getpass('ZIOCHUB password: ')
            except (EOFError, KeyboardInterrupt):
                _die('Password input cancelled', 130)
    elif args.password is None:
        try:
            password = getpass.getpass('ZIOCHUB password: ')
        except (EOFError, KeyboardInterrupt):
            _die('Password input cancelled', 130)
    else:
        password = args.password

    if not password:
        _die('Missing password: set ZIOCHUB_PASSWORD, enter at prompt, or pass --password (discouraged on CLI)')

    try:
        import requests
    except ImportError:
        _die('Install requests: pip install requests', 2)

    from utils.http_identity import configure_requests_session

    s = requests.Session()
    configure_requests_session(s)
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
        data={'username': args.user, 'password': password},
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
