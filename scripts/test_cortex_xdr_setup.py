#!/usr/bin/env python3
"""
Diagnose Cortex XDR integration import and settings (run on the Ubuntu server).

  cd /path/to/ioc_submission
  source venv/bin/activate
  python scripts/test_cortex_xdr_setup.py
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main() -> int:
    print('ZIoCHub root:', ROOT)
    print('--- import utils.cortex_xdr ---')
    try:
        from utils import cortex_xdr as cx
        print('OK:', cx.__file__)
    except Exception as e:
        print('FAIL import utils.cortex_xdr:', type(e).__name__, e)
        return 1

    print('--- Flask app + DB settings ---')
    try:
        import app as zio_app
        with zio_app.app.app_context():
            g = cx.cortex_xdr_settings_dict()
            for k in sorted(g.keys()):
                v = g[k]
                if 'api_key' in k and v:
                    v = '***' + v[-4:] if len(v) > 4 else '***'
                print(f'  {k} = {v!r}')
            print('--- dry-run test_connection (no HTTP if missing config) ---')
            out = cx.cortex_xdr_test_connection(g)
            print('success:', out.get('success'))
            for step in out.get('steps') or []:
                print(' ', step.get('status'), step.get('step'), '-', (step.get('message') or '')[:200])
    except Exception as e:
        print('FAIL app context / test:', type(e).__name__, e)
        import traceback
        traceback.print_exc()
        return 1

    print('--- done ---')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
