#!/usr/bin/env python3
"""
Diagnose Google SecOps (Chronicle Data Table) integration (run on the Ubuntu server).

  cd /path/to/ziochub
  source venv/bin/activate
  python scripts/test_google_secops_setup.py
  python scripts/test_google_secops_setup.py --config-only
  python scripts/test_google_secops_setup.py --roundtrip
"""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _print_steps(steps) -> None:
    for step in steps or []:
        status = step.get('status', '?')
        name = step.get('step', '')
        msg = (step.get('message') or '')[:400]
        print(f'  [{status}] {name}: {msg}')


def main() -> int:
    parser = argparse.ArgumentParser(description='ZIoCHub Google SecOps troubleshooting')
    parser.add_argument(
        '--config-only',
        action='store_true',
        help='Validate saved settings locally (no OAuth / HTTP)',
    )
    parser.add_argument(
        '--roundtrip',
        action='store_true',
        help='After connection test, bulkCreate one *.invalid row and delete it',
    )
    args = parser.parse_args()

    print('ZIoCHub root:', ROOT)
    print('--- import utils.google_secops ---')
    try:
        from utils import google_secops as gs
        print('OK:', gs.__file__)
    except Exception as e:
        print('FAIL import utils.google_secops:', type(e).__name__, e)
        return 1

    print('--- Flask app + DB settings ---')
    try:
        import app as zio_app
        with zio_app.app.app_context():
            settings = gs.google_secops_settings_dict()
            secret_keys = frozenset({
                'google_secops_credentials_json',
                'google_secops_gateway_api_key',
                'google_secops_gateway_oauth_client_secret',
            })
            resolved_mode = gs.google_secops_connection_mode(settings)
            print(f'  connection_mode (resolved) = {resolved_mode!r}')
            for k in sorted(settings.keys()):
                v = settings[k]
                if k in secret_keys and v:
                    if k == 'google_secops_credentials_json':
                        try:
                            import json
                            info = json.loads(v)
                            email = (info.get('client_email') or '?') if isinstance(info, dict) else '?'
                            v = f'<JSON ok, client_email={email}>'
                        except Exception:
                            v = '<invalid JSON>'
                    else:
                        v = '<set, hidden>'
                print(f'  {k} = {v!r}')

            mode = 'config-only' if args.config_only else ('roundtrip' if args.roundtrip else 'connection')
            print(f'--- test ({mode}) ---')
            out = gs.google_secops_test_connection(
                settings,
                roundtrip=args.roundtrip,
                config_only=args.config_only,
            )
            print('success:', out.get('success'))
            _print_steps(out.get('steps'))
    except Exception as e:
        print('FAIL app context / test:', type(e).__name__, e)
        import traceback
        traceback.print_exc()
        return 1

    print('--- done ---')
    return 0 if out.get('success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
