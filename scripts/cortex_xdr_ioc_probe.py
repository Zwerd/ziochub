#!/usr/bin/env python3
"""
Manual Cortex XDR IOC API probe — test whether an IOC type/value can be pushed.

Exercises the same auth/signing as ZIoCHub (utils.cortex_xdr) and can try multiple API
surfaces so you can verify behaviour on your tenant:

  - POST .../indicators/insert_jsons   (ZIoCHub production path; docs: HASH, IP, DOMAIN_NAME, FILENAME)
  - POST .../indicators/insert         (Instance Admin; docs add PATH, MIXED)
  - POST .../indicators/get            (lookup by indicator value after insert)
  - POST .../indicators/delete         (optional cleanup with --delete-after)

``--type`` is sent **as-is** in the request body (no ZIoCHub alias mapping). Use the exact
Cortex type your tenant accepts (HASH, URL, EMAIL_ADDRESS, PATH, MIXED, custom values, etc.).

Environment variables (optional defaults):

  CORTEX_XDR_BASE_URL      https://api-xx.paloaltonetworks.com
  CORTEX_XDR_API_KEY_ID
  CORTEX_XDR_API_KEY
  CORTEX_XDR_SECURITY_LEVEL   advanced | standard  (default: advanced)
  CORTEX_XDR_VERIFY_SSL       true | false       (default: true)

Usage (on Ubuntu server, from project root):

  source venv/bin/activate

  # Load credentials from ZIoCHub Admin → Integrations → Cortex XDR (SQLite system_settings)
  # --type is sent as-is to Cortex (no alias mapping). Examples:
  python scripts/cortex_xdr_ioc_probe.py --from-db --type URL --value 'https://evil.example/phish'
  python scripts/cortex_xdr_ioc_probe.py --from-db --type EMAIL_ADDRESS --value 'phish@evil.example'
  python scripts/cortex_xdr_ioc_probe.py --from-db --type HASH --value 'abc123...'

  # Explicit credentials (API key: env or secure prompt — avoid passing on CLI)
  python scripts/cortex_xdr_ioc_probe.py \\
    --base-url https://api-xx.paloaltonetworks.com \\
    --api-key-id 12 --type DOMAIN_NAME --value evil.example \\
    --action auto --delete-after

  # Single endpoint only
  python scripts/cortex_xdr_ioc_probe.py --from-db -t PATH -v 'https://x/y' \\
    --action insert-jsons

  # Dry-run: print payloads only
  python scripts/cortex_xdr_ioc_probe.py --from-db -t URL -v 'https://x/y' --dry-run

  -k / --insecure   Skip TLS certificate verification.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys
from typing import Any, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

_API_KEY_ARG_UNSET = object()

_INSERT_JSONS_TYPES = frozenset({'HASH', 'IP', 'DOMAIN_NAME', 'FILENAME'})
_INSERT_TYPES = frozenset({'HASH', 'IP', 'PATH', 'DOMAIN_NAME', 'FILENAME', 'MIXED'})

_CORTEX_SETTING_KEYS = (
    'cortex_xdr_enabled',
    'cortex_xdr_base_url',
    'cortex_xdr_api_key_id',
    'cortex_xdr_api_key',
    'cortex_xdr_verify_ssl',
    'cortex_xdr_hash_blocklist_enabled',
    'cortex_xdr_security_level',
    'cortex_xdr_comment_mode',
)


def _die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def _resolve_cortex_type(args: argparse.Namespace) -> str:
    """Return the Cortex API ``type`` field exactly as the operator specified."""
    raw = (args.cortex_type or args.type or '').strip()
    if not raw:
        _die('Missing --type (Cortex API type, e.g. HASH, IP, DOMAIN_NAME, URL, EMAIL_ADDRESS, PATH, MIXED)')
    return raw


def _resolve_api_key(cli_val: Any) -> str:
    if cli_val is _API_KEY_ARG_UNSET:
        key = (os.environ.get('CORTEX_XDR_API_KEY') or '').strip()
        if not key:
            try:
                key = getpass.getpass('Cortex XDR API key secret: ')
            except (EOFError, KeyboardInterrupt):
                _die('API key input cancelled', 130)
        return key
    if cli_val is None:
        try:
            return getpass.getpass('Cortex XDR API key secret: ')
        except (EOFError, KeyboardInterrupt):
            _die('API key input cancelled', 130)
    return str(cli_val or '').strip()


def _resolve_ziochub_db_path() -> str:
    """Locate ziochub.db without importing Flask (same rules as app.py / config.py)."""
    data_dir = (os.environ.get('ZIOCHUB_DATA_DIR') or '').strip()
    if not data_dir:
        try:
            import config as _config
            data_dir = (_config and _config.DATA_DIR) or ''
        except ImportError:
            data_dir = ''
    if not data_dir:
        data_dir = os.path.join(ROOT, 'data')

    db_path = (os.environ.get('ZIOCHUB_DB_PATH') or '').strip()
    if not db_path:
        try:
            import config as _config
            db_path = (_config and getattr(_config, 'DB_PATH', None)) or ''
        except ImportError:
            db_path = ''
    if not db_path:
        db_path = os.path.join(data_dir, 'ziochub.db')
    return os.path.abspath(db_path)


def _load_settings_from_sqlite(db_path: Optional[str] = None) -> dict[str, str]:
    """Read cortex_xdr_* rows from system_settings (stdlib sqlite3 only)."""
    path = os.path.abspath(db_path or _resolve_ziochub_db_path())
    if not os.path.isfile(path):
        _die(
            f'--from-db: SQLite DB not found: {path}\n'
            'Set ZIOCHUB_DATA_DIR or run from the ZIoCHub project root on the server.'
        )
    placeholders = ','.join('?' for _ in _CORTEX_SETTING_KEYS)
    sql = f'SELECT key, value FROM system_settings WHERE key IN ({placeholders})'
    try:
        conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    except sqlite3.Error:
        conn = sqlite3.connect(path)
    try:
        cur = conn.execute(sql, _CORTEX_SETTING_KEYS)
        rows = cur.fetchall()
    except sqlite3.Error as e:
        _die(f'--from-db: failed reading {path}: {e}')
    finally:
        conn.close()
    out = {k: '' for k in _CORTEX_SETTING_KEYS}
    for key, value in rows:
        if key in out:
            out[key] = (value or '') if value is not None else ''
    return out


def _load_settings_from_db() -> dict[str, str]:
    """Load Integrations → Cortex XDR settings from ZIoCHub SQLite (no Flask required)."""
    db_path = _resolve_ziochub_db_path()
    print(f'Reading Cortex settings from: {db_path}', file=sys.stderr)
    return _load_settings_from_sqlite(db_path)


def _resolve_connection(args: argparse.Namespace) -> dict[str, Any]:
    g: dict[str, str] = {}
    if args.from_db:
        g = _load_settings_from_db()

    base = (args.base_url or g.get('cortex_xdr_base_url') or os.environ.get('CORTEX_XDR_BASE_URL') or '').strip()
    key_id = (args.api_key_id or g.get('cortex_xdr_api_key_id') or os.environ.get('CORTEX_XDR_API_KEY_ID') or '').strip()
    if args.from_db:
        api_key = (g.get('cortex_xdr_api_key') or '').strip()
        if args.api_key is not _API_KEY_ARG_UNSET and args.api_key:
            api_key = str(args.api_key).strip()
        if not api_key:
            api_key = _resolve_api_key(_API_KEY_ARG_UNSET)
    else:
        api_key = _resolve_api_key(args.api_key)

    sec_raw = (
        args.security_level
        or g.get('cortex_xdr_security_level')
        or os.environ.get('CORTEX_XDR_SECURITY_LEVEL')
        or 'advanced'
    ).strip().lower()
    security_level = 'standard' if sec_raw == 'standard' else 'advanced'

    verify_env = (os.environ.get('CORTEX_XDR_VERIFY_SSL', '') or g.get('cortex_xdr_verify_ssl', 'true')).strip().lower()
    verify_ssl = verify_env in ('true', '1', 'yes') and not args.insecure

    if not base:
        _die('Missing --base-url, CORTEX_XDR_BASE_URL, or --from-db with saved cortex_xdr_base_url')
    if not key_id:
        _die('Missing --api-key-id, CORTEX_XDR_API_KEY_ID, or saved cortex_xdr_api_key_id')
    if not api_key:
        _die('Missing API key: saved cortex_xdr_api_key, CORTEX_XDR_API_KEY, or --api-key / prompt')

    from utils.cortex_xdr import sanitize_cortex_base_url

    return {
        'base_url': sanitize_cortex_base_url(base),
        'api_key_id': key_id,
        'api_key': api_key,
        'security_level': security_level,
        'verify_ssl': verify_ssl,
    }


def _root_v1(base_url: str) -> str:
    from utils.cortex_xdr import _public_api_v1_root
    return _public_api_v1_root(base_url)


def _headers(conn: dict[str, Any], *, iocs_source: bool = False) -> dict[str, str]:
    from utils.cortex_xdr import _sign_headers
    return _sign_headers(
        conn['api_key_id'],
        conn['api_key'],
        tim_source=iocs_source,
        security_level=conn['security_level'],
    )


def _post(
    conn: dict[str, Any],
    subpath: str,
    body: dict[str, Any],
    *,
    iocs_source: bool = False,
    timeout_sec: Optional[float] = None,
) -> tuple[int, Optional[dict[str, Any]], str]:
    from utils.cortex_xdr import _http_json_post

    root = _root_v1(conn['base_url'])
    url = root.rstrip('/') + '/' + subpath.lstrip('/')
    return _http_json_post(
        url,
        body,
        _headers(conn, iocs_source=iocs_source),
        conn['verify_ssl'],
        timeout_sec=timeout_sec,
    )


def _print_step(title: str) -> None:
    print(f'\n=== {title} ===')


def _print_result(code: int, data: Optional[dict[str, Any]], raw: str, *, url_hint: str = '') -> None:
    if url_hint:
        print(f'POST {url_hint}')
    print(f'HTTP {code}')
    if data is not None:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif raw:
        print(raw[:4000])


def _interpret_insert_jsons(data: Optional[dict[str, Any]], raw: str) -> tuple[bool, str]:
    from utils.cortex_xdr import _interpret_tim_reply
    return _interpret_tim_reply(data, op='insert_jsons')


def _interpret_insert_legacy(data: Optional[dict[str, Any]]) -> tuple[bool, str]:
    if not isinstance(data, dict):
        return False, 'insert: empty or non-JSON response'
    if data.get('errors'):
        errs = data.get('errors')
        return False, f'insert errors: {errs!s}'[:900]
    added = data.get('added_objects') or []
    updated = data.get('updated_objects') or []
    if added or updated:
        parts = []
        for o in (added + updated)[:3]:
            if isinstance(o, dict):
                parts.append(f"id={o.get('id')} status={o.get('status')}")
        return True, 'insert_ok ' + '; '.join(parts)
    rep = data.get('reply')
    if isinstance(rep, dict) and rep.get('success') is True:
        return True, 'insert_ok'
    err = data.get('err_msg') or (rep or {}).get('err_msg') if isinstance(rep, dict) else None
    if err:
        return False, f'insert: {err}'[:900]
    return False, 'insert: no added/updated objects'


def _build_insert_jsons_record(indicator: str, cortex_type: str, comment: str) -> dict[str, Any]:
    return {
        'indicator': indicator,
        'type': cortex_type,
        'severity': 'HIGH',
        'reputation': 'BAD',
        'comment': comment[:4000],
        'expiration_date': -1,
    }


def _build_insert_record(indicator: str, cortex_type: str, comment: str) -> dict[str, Any]:
    return {
        'indicator': indicator,
        'type': cortex_type,
        'severity': 'SEV_040_HIGH',
        'reputation': 'BAD',
        'reliability': 'A',
        'comment': comment[:4000],
        'expiration_date': -1,
        'default_expiration_enabled': True,
    }


def _run_probe(conn: dict[str, Any]) -> bool:
    _print_step('Probe indicators/get (auth + IOC API reachability)')
    root = _root_v1(conn['base_url'])
    url = root.rstrip('/') + '/indicators/get'
    body = {'request_data': {}}
    code, data, raw = _post(conn, 'indicators/get', body, iocs_source=False)
    _print_result(code, data, raw, url_hint=url)
    ok = 200 <= code < 300
    if isinstance(data, dict) and data.get('reply') is not None:
        ok = ok and True
    print('→', 'OK' if ok else 'FAIL')
    return ok


def _run_get(conn: dict[str, Any], value: str) -> bool:
    _print_step(f'Get indicator EQ {value!r}')
    body = {
        'request_data': {
            'extended_view': True,
            'filters': [
                {'field': 'indicator', 'operator': 'EQ', 'value': [value]},
            ],
            'search_from': 0,
            'search_to': 100,
        },
    }
    code, data, raw = _post(conn, 'indicators/get', body, iocs_source=False)
    _print_result(code, data, raw)
    ok = 200 <= code < 300
    if isinstance(data, dict):
        objs = data.get('objects') or (data.get('reply') or {}).get('objects') if isinstance(data.get('reply'), dict) else None
        if objs is None and isinstance(data.get('reply'), dict):
            objs = data['reply'].get('objects')
        count = data.get('objects_count')
        if count is None and isinstance(data.get('reply'), dict):
            count = data['reply'].get('objects_count')
        print(f'objects_count={count!r}')
        if objs:
            for o in objs[:5]:
                if isinstance(o, dict):
                    print(
                        f"  rule_id={o.get('rule_id')} type={o.get('type')} "
                        f"indicator={o.get('indicator')!r} severity={o.get('severity')}"
                    )
    print('→', 'FOUND' if ok else 'FAIL')
    return ok


def _run_insert_jsons(
    conn: dict[str, Any],
    indicator: str,
    cortex_type: str,
    comment: str,
    *,
    dry_run: bool,
) -> tuple[bool, str]:
    _print_step(f'insert_jsons type={cortex_type} indicator={indicator!r}')
    if cortex_type not in _INSERT_JSONS_TYPES:
        print(f'Note: official insert_jsons allowed types are {sorted(_INSERT_JSONS_TYPES)} — testing anyway.')
    rec = _build_insert_jsons_record(indicator, cortex_type, comment)
    body = {'request_data': [rec], 'validate': True}
    if dry_run:
        print(json.dumps(body, ensure_ascii=False, indent=2))
        return False, 'dry_run'
    code, data, raw = _post(conn, 'indicators/insert_jsons', body, iocs_source=True)
    _print_result(code, data, raw)
    ok, msg = _interpret_insert_jsons(data, raw)
    if not (200 <= code < 300):
        ok = False
        msg = f'HTTP {code}: {raw[:240]}'
    print('→', 'OK' if ok else 'FAIL', msg)
    return ok, msg


def _run_insert(
    conn: dict[str, Any],
    indicator: str,
    cortex_type: str,
    comment: str,
    *,
    dry_run: bool,
) -> tuple[bool, str]:
    _print_step(f'indicators/insert type={cortex_type} indicator={indicator!r} (Instance Admin API)')
    if cortex_type not in _INSERT_TYPES:
        print(f'Note: official insert allowed types are {sorted(_INSERT_TYPES)} — testing anyway.')
    rec = _build_insert_record(indicator, cortex_type, comment)
    body = {'request_data': [rec]}
    if dry_run:
        print(json.dumps(body, ensure_ascii=False, indent=2))
        return False, 'dry_run'
    code, data, raw = _post(conn, 'indicators/insert', body, iocs_source=False)
    _print_result(code, data, raw)
    ok, msg = _interpret_insert_legacy(data)
    if not (200 <= code < 300):
        ok = False
        if code == 403:
            msg = f'HTTP 403 — likely missing Instance Administrator RBAC for indicators/insert. {raw[:200]}'
        else:
            msg = f'HTTP {code}: {raw[:240]}'
    print('→', 'OK' if ok else 'FAIL', msg)
    return ok, msg


def _run_delete(conn: dict[str, Any], value: str, *, dry_run: bool) -> bool:
    _print_step(f'Delete indicator {value!r}')
    body = {
        'request_data': {
            'filters': [
                {'field': 'indicator', 'operator': 'EQ', 'value': [value]},
            ],
        },
    }
    if dry_run:
        print(json.dumps(body, ensure_ascii=False, indent=2))
        return False
    code, data, raw = _post(conn, 'indicators/delete', body, iocs_source=False)
    _print_result(code, data, raw)
    from utils.cortex_xdr import _interpret_tim_reply
    ok, msg = _interpret_tim_reply(data, op='indicators/delete')
    if not (200 <= code < 300):
        ok = False
    print('→', 'OK' if ok else 'FAIL', msg)
    return ok


def _attempts_for_args(args: argparse.Namespace) -> list[tuple[str, str]]:
    cortex_type = _resolve_cortex_type(args)

    if args.try_all_types:
        out: list[tuple[str, str]] = []
        for ct in sorted(_INSERT_JSONS_TYPES):
            out.append(('insert_jsons', ct))
        for ct in sorted(_INSERT_TYPES):
            out.append(('insert', ct))
        return out

    if args.action == 'insert-jsons':
        return [('insert_jsons', cortex_type)]
    if args.action == 'insert':
        return [('insert', cortex_type)]

    # auto: try both endpoints with the same operator-provided type (unless --endpoint limits it)
    endpoint = (args.endpoint or 'both').strip().lower()
    if endpoint == 'insert-jsons':
        return [('insert_jsons', cortex_type)]
    if endpoint == 'insert':
        return [('insert', cortex_type)]
    return [('insert_jsons', cortex_type), ('insert', cortex_type)]


def main() -> None:
    epilog = """
Examples:
  %(prog)s --from-db -t URL -v 'https://evil.example/login'
  %(prog)s --from-db -t EMAIL_ADDRESS -v 'user@evil.example' --delete-after
  %(prog)s --from-db -t PATH -v 'https://evil.example/x' --action insert
  %(prog)s --from-db -t HASH1 -v 'deadbeef...' --endpoint insert-jsons
  %(prog)s --from-db -t URL -v 'https://evil.example/x' --try-all-types --dry-run
"""
    p = argparse.ArgumentParser(
        description='Probe Cortex XDR IOC insert APIs for a type+value (manual tenant testing).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    p.add_argument('--from-db', action='store_true',
                   help='Load cortex_xdr_* settings from ZIoCHub SQLite (requires app + venv on server)')
    p.add_argument('--base-url', default='', help='Cortex API host (or CORTEX_XDR_BASE_URL)')
    p.add_argument('--api-key-id', default=os.environ.get('CORTEX_XDR_API_KEY_ID', ''),
                   help='API key ID (or CORTEX_XDR_API_KEY_ID)')
    p.add_argument(
        '--api-key',
        nargs='?',
        default=_API_KEY_ARG_UNSET,
        const=None,
        metavar='SECRET',
        help='API key secret. Omit for env CORTEX_XDR_API_KEY or secure prompt.',
    )
    p.add_argument('--security-level', choices=('advanced', 'standard'), default='',
                   help='Must match key type in Cortex console (default: advanced)')
    p.add_argument('--insecure', '-k', action='store_true', help='Disable TLS verification')
    p.add_argument('--type', '-t', required=True,
                   help='Cortex API type sent in the request body as-is (e.g. HASH, IP, DOMAIN_NAME, URL, EMAIL_ADDRESS, PATH, MIXED, HASH1)')
    p.add_argument('--value', '-v', required=True, help='IOC value to test')
    p.add_argument('--cortex-type', default='',
                   help='Optional alias for --type (if set, overrides --type in the payload)')
    p.add_argument(
        '--action',
        choices=('auto', 'probe', 'get', 'insert-jsons', 'insert', 'delete'),
        default='auto',
        help='auto=probe then try insert(s); probe/get/insert-jsons/insert/delete=single step',
    )
    p.add_argument(
        '--endpoint',
        choices=('both', 'insert-jsons', 'insert'),
        default='both',
        help='With --action auto: which API surface to call (default: both, same --type each time)',
    )
    p.add_argument('--try-all-types', action='store_true',
                   help='Ignore --type; try every documented type on both endpoints (noisy; use --dry-run first)')
    p.add_argument('--comment', default='ziochub-cortex-xdr-ioc-probe',
                   help='Comment field on test IOC rows')
    p.add_argument('--dry-run', action='store_true', help='Print request bodies only; no HTTP insert/delete')
    p.add_argument('--delete-after', action='store_true',
                   help='After a successful insert attempt, call indicators/delete for --value')
    p.add_argument('--skip-probe', action='store_true', help='Skip initial indicators/get probe in auto mode')
    args = p.parse_args()

    value = (args.value or '').strip()
    if not value:
        _die('--value is required')

    conn = _resolve_connection(args)
    print('Cortex target:', conn['base_url'])
    print('API key ID:', conn['api_key_id'])
    print('Security level:', conn['security_level'])
    print('Verify TLS:', conn['verify_ssl'])
    print('Cortex type:', _resolve_cortex_type(args), '| value:', value)

    if args.action == 'probe':
        raise SystemExit(0 if _run_probe(conn) else 2)
    if args.action == 'get':
        raise SystemExit(0 if _run_get(conn, value) else 2)
    if args.action == 'delete':
        raise SystemExit(0 if _run_delete(conn, value, dry_run=args.dry_run) else 2)

    if args.action == 'insert-jsons':
        ok, _ = _run_insert_jsons(
            conn, value, _resolve_cortex_type(args),
            args.comment, dry_run=args.dry_run,
        )
        if ok and args.delete_after and not args.dry_run:
            _run_delete(conn, value, dry_run=False)
        raise SystemExit(0 if ok else 2)

    if args.action == 'insert':
        ok, _ = _run_insert(
            conn, value, _resolve_cortex_type(args),
            args.comment, dry_run=args.dry_run,
        )
        if ok and args.delete_after and not args.dry_run:
            _run_delete(conn, value, dry_run=False)
        raise SystemExit(0 if ok else 2)

    # auto
    if not args.skip_probe and not args.dry_run:
        if not _run_probe(conn):
            print('\nProbe failed — fix base URL / API key / security level before insert tests.', file=sys.stderr)

    attempts = _attempts_for_args(args)
    print(f'\nPlanned attempts ({len(attempts)}):')
    for ep, ct in attempts:
        print(f'  - {ep}  cortex_type={ct}')

    any_ok = False
    last_ok_endpoint = ''
    for ep, cortex_type in attempts:
        if ep == 'insert_jsons':
            ok, _ = _run_insert_jsons(conn, value, cortex_type, args.comment, dry_run=args.dry_run)
        else:
            ok, _ = _run_insert(conn, value, cortex_type, args.comment, dry_run=args.dry_run)
        if ok:
            any_ok = True
            last_ok_endpoint = f'{ep}:{cortex_type}'
            if not args.try_all_types:
                break

    if not args.dry_run:
        _run_get(conn, value)

    if any_ok and args.delete_after and not args.dry_run:
        _run_delete(conn, value, dry_run=False)

    if args.dry_run:
        print('\nDry-run complete (no inserts sent).')
        raise SystemExit(0)

    if any_ok:
        print(f'\nSUCCESS: at least one insert worked ({last_ok_endpoint}).')
        raise SystemExit(0)

    print(
        '\nNo insert attempt succeeded. Pass the exact Cortex type your tenant expects '
        '(e.g. --type PATH, --type EMAIL_ADDRESS, --type URL). '
        'Use --endpoint insert for indicators/insert (Instance Administrator RBAC). '
        'Use --try-all-types --dry-run to sweep documented types.',
        file=sys.stderr,
    )
    raise SystemExit(2)


if __name__ == '__main__':
    main()
