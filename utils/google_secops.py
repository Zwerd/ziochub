"""
Google Security Operations (SecOps, Chronicle) — IOC outbound via **Data Table** REST API.

**Connection modes**
- **direct:** GCP service account JSON → OAuth to native Chronicle host
  (``https://<location>-chronicle.googleapis.com`` or custom REST API base).
- **apigee:** Internal API Gateway base URL + API key or OAuth2 client credentials;
  same ``v1beta/.../dataTables/...`` paths appended to the gateway base.

**Why Data Tables (not Ingestion API)?** Chronicle's Ingestion API (``malachite-ingestion``) ships raw
log/event payloads into the tenant. ZIoCHub instead publishes IOCs as rows in a SecOps **Data Table** —
a reference dataset analysts can **join to UDM events in Search**, dashboards, and detection logic.
That lets hunts pivot from a TI-published indicator (domain, IP, hash, …) to matching log entries without
maintaining a separate list. Rows are removed on revoke/expiry so correlation stays aligned with ZIoCHub.

**Runtime paths**
- **Push (create/reactivate):** Chronicle REST ``v1beta`` → ``dataTableRows:bulkCreate`` (two columns:
  type slug, value).
- **Remove (delete/expiry):** ``dataTableRows.list`` (filter by value) + row ``delete``.
- **Diagnostics only (direct mode):** optional ``GET /v2/logtypes`` on Ingestion host.

OAuth scope ``https://www.googleapis.com/auth/chronicle`` is required for Data Table operations in
direct mode; IAM such as ``chronicle.dataTableRows.bulkCreate``, ``.list``, ``.delete``, and
``chronicle.dataTables.get``.
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SEC = 90

MALACHITE_INGESTION_SCOPE = 'https://www.googleapis.com/auth/malachite-ingestion'
CHRONICLE_SCOPE = 'https://www.googleapis.com/auth/chronicle'
DEFAULT_INGESTION_HOST_US = 'https://malachiteingestion-pa.googleapis.com'

API_VERSION = 'v1beta'

_SCOPES = (CHRONICLE_SCOPE, MALACHITE_INGESTION_SCOPE)

CONNECTION_MODE_DIRECT = 'direct'
CONNECTION_MODE_APIGEE = 'apigee'
GATEWAY_AUTH_API_KEY = 'api_key'
GATEWAY_AUTH_OAUTH2 = 'oauth2'

_OAUTH_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_OAUTH_TOKEN_CACHE_MARGIN_SEC = 30


def _get_setting(key: str, default: str = '') -> str:
    import app as _app
    return _app._get_setting(key, default)


def google_secops_enabled(settings: Optional[dict[str, str]] = None) -> bool:
    g = settings or google_secops_settings_dict()
    return (g.get('google_secops_enabled', 'false') or 'false').strip().lower() in ('true', '1', 'yes')


def google_secops_settings_dict() -> dict[str, str]:
    keys = (
        'google_secops_enabled',
        'google_secops_connection_mode',
        'google_secops_base_url',
        'google_secops_chronicle_api_base',
        'google_secops_gateway_base_url',
        'google_secops_gateway_auth_method',
        'google_secops_gateway_api_key_header',
        'google_secops_gateway_api_key',
        'google_secops_gateway_oauth_client_id',
        'google_secops_gateway_oauth_client_secret',
        'google_secops_gateway_oauth_token_url',
        'google_secops_gateway_custom_headers',
        'google_secops_project_number',
        'google_secops_location',
        'google_secops_instance_id',
        'google_secops_customer_id',
        'google_secops_data_table_id',
        'google_secops_credentials_json',
        'google_secops_verify_ssl',
    )
    return {k: _get_setting(k, '') for k in keys}


def google_secops_connection_mode(g: dict[str, str]) -> str:
    raw = (g.get('google_secops_connection_mode') or CONNECTION_MODE_DIRECT).strip().lower()
    if raw in (CONNECTION_MODE_APIGEE, 'gateway', 'api_gateway', 'apigee'):
        return CONNECTION_MODE_APIGEE
    return CONNECTION_MODE_DIRECT


def google_secops_gateway_auth_method(g: dict[str, str]) -> str:
    raw = (g.get('google_secops_gateway_auth_method') or GATEWAY_AUTH_API_KEY).strip().lower()
    if raw in (GATEWAY_AUTH_OAUTH2, 'oauth', 'oauth2', 'client_credentials'):
        return GATEWAY_AUTH_OAUTH2
    return GATEWAY_AUTH_API_KEY


def normalize_google_secops_connection_mode(val: Any) -> str:
    raw = str(val or '').strip().lower()
    if raw in (CONNECTION_MODE_APIGEE, 'gateway', 'api_gateway', 'apigee'):
        return CONNECTION_MODE_APIGEE
    return CONNECTION_MODE_DIRECT


def normalize_google_secops_gateway_auth_method(val: Any) -> str:
    raw = str(val or '').strip().lower()
    if raw in (GATEWAY_AUTH_OAUTH2, 'oauth', 'oauth2', 'client_credentials'):
        return GATEWAY_AUTH_OAUTH2
    return GATEWAY_AUTH_API_KEY


def normalize_google_secops_gateway_custom_headers(val: Any) -> str:
    """Validate and serialize custom headers as JSON array of {key, value}."""
    if val is None:
        return '[]'
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return '[]'
        try:
            val = json.loads(s)
        except (TypeError, ValueError) as e:
            raise ValueError(f'google_secops_gateway_custom_headers: invalid JSON ({e})') from e
    if not isinstance(val, list):
        raise ValueError('google_secops_gateway_custom_headers must be a JSON array')
    out: list[dict[str, str]] = []
    for item in val:
        if not isinstance(item, dict):
            continue
        key = str(item.get('key') or item.get('name') or '').strip()
        value = str(item.get('value') or '').strip()
        if not key:
            continue
        out.append({'key': key, 'value': value})
    return json.dumps(out, ensure_ascii=False)


def parse_google_secops_gateway_custom_headers(g: dict[str, str]) -> dict[str, str]:
    raw = (g.get('google_secops_gateway_custom_headers') or '').strip()
    if not raw:
        return {}
    try:
        items = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(items, list):
        return {}
    headers: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get('key') or item.get('name') or '').strip()
        if not key:
            continue
        headers[key] = str(item.get('value') or '')
    return headers


def _ingestion_api_base(g: dict[str, str]) -> str:
    raw = (g.get('google_secops_base_url') or '').strip().rstrip('/')
    return raw if raw else DEFAULT_INGESTION_HOST_US


def _chronicle_rest_base(g: dict[str, str]) -> str:
    raw = (g.get('google_secops_chronicle_api_base') or '').strip().rstrip('/')
    if raw:
        return raw
    loc = (g.get('google_secops_location') or '').strip()
    if loc:
        return f'https://{loc}-chronicle.googleapis.com'
    return ''


def _api_rest_base(g: dict[str, str]) -> str:
    """Chronicle REST base URL for Data Table API calls (direct or API Gateway)."""
    if google_secops_connection_mode(g) == CONNECTION_MODE_APIGEE:
        return (g.get('google_secops_gateway_base_url') or '').strip().rstrip('/')
    return _chronicle_rest_base(g)


def _data_table_parent(g: dict[str, str]) -> Optional[str]:
    proj = (g.get('google_secops_project_number') or '').strip()
    loc = (g.get('google_secops_location') or '').strip()
    inst = (g.get('google_secops_instance_id') or '').strip() or (g.get('google_secops_customer_id') or '').strip()
    tid = (g.get('google_secops_data_table_id') or '').strip()
    if not all([proj, loc, inst, tid]):
        return None
    return f'projects/{proj}/locations/{loc}/instances/{inst}/dataTables/{tid}'


def _ioc_type_slug(ioc_type: str) -> str:
    t = (ioc_type or '').strip()
    return {
        'IP': 'ip',
        'Domain': 'domain',
        'URL': 'url',
        'Hash': 'hash',
        'Email': 'email',
        'YARA': 'yara',
    }.get(t, t.lower() or 'unknown')


def _row_matches_ioc(row: dict[str, Any], slug: str, value: str) -> bool:
    vals = row.get('values')
    if not isinstance(vals, list) or len(vals) < 2:
        return False
    c0 = str(vals[0]).strip().lower()
    c1 = str(vals[1]).strip()
    return c0 == slug and c1.lower() == value.strip().lower()


def _load_credentials(
    g: dict[str, str],
    verify_ssl: bool,
):
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account
    import requests

    raw = (g.get('google_secops_credentials_json') or '').strip()
    if not raw:
        raise ValueError('google_secops_credentials_json is empty')
    info = json.loads(raw)
    if not isinstance(info, dict):
        raise ValueError('Credentials JSON must be an object')
    creds = service_account.Credentials.from_service_account_info(info, scopes=_SCOPES)
    session = requests.Session()
    session.verify = verify_ssl
    creds.refresh(Request(session=session))
    return creds, session


def _oauth_cache_key(g: dict[str, str]) -> str:
    return '|'.join([
        (g.get('google_secops_gateway_oauth_token_url') or '').strip(),
        (g.get('google_secops_gateway_oauth_client_id') or '').strip(),
    ])


def _fetch_gateway_oauth_token(g: dict[str, str], session) -> str:
    token_url = (g.get('google_secops_gateway_oauth_token_url') or '').strip()
    client_id = (g.get('google_secops_gateway_oauth_client_id') or '').strip()
    client_secret = (g.get('google_secops_gateway_oauth_client_secret') or '').strip()
    if not token_url:
        raise ValueError('OAuth2 token URL is empty')
    if not client_id or not client_secret:
        raise ValueError('OAuth2 client ID and client secret are required')

    cache_key = _oauth_cache_key(g)
    cached = _OAUTH_TOKEN_CACHE.get(cache_key)
    if cached:
        token, expires_at = cached
        if time.time() < expires_at - _OAUTH_TOKEN_CACHE_MARGIN_SEC:
            return token

    r = session.post(
        token_url,
        data={
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=REQUEST_TIMEOUT_SEC,
    )
    if r.status_code not in (200, 201):
        raise ValueError(f'OAuth2 token request failed: HTTP {r.status_code} {r.text[:200]}')
    try:
        payload = r.json()
    except json.JSONDecodeError as e:
        raise ValueError(f'OAuth2 token response invalid JSON: {e}') from e
    if not isinstance(payload, dict):
        raise ValueError('OAuth2 token response must be a JSON object')
    token = (payload.get('access_token') or '').strip()
    if not token:
        raise ValueError('OAuth2 token response missing access_token')
    expires_in = payload.get('expires_in')
    try:
        ttl = max(60, int(expires_in)) if expires_in is not None else 3600
    except (TypeError, ValueError):
        ttl = 3600
    _OAUTH_TOKEN_CACHE[cache_key] = (token, time.time() + ttl)
    return token


def _merge_custom_headers(base: dict[str, str], g: dict[str, str]) -> dict[str, str]:
    merged = dict(parse_google_secops_gateway_custom_headers(g))
    for key, value in base.items():
        merged[key] = value
    return merged


def _build_request_session_and_headers(g: dict[str, str], verify_ssl: bool) -> tuple[Any, dict[str, str]]:
    import requests

    session = requests.Session()
    session.verify = verify_ssl
    mode = google_secops_connection_mode(g)

    if mode == CONNECTION_MODE_DIRECT:
        creds, session = _load_credentials(g, verify_ssl)
        headers = _merge_custom_headers(
            {'Authorization': f'Bearer {creds.token}', 'Content-Type': 'application/json'},
            g,
        )
        return session, headers

    auth = google_secops_gateway_auth_method(g)
    if auth == GATEWAY_AUTH_OAUTH2:
        token = _fetch_gateway_oauth_token(g, session)
        core = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    else:
        header_name = (g.get('google_secops_gateway_api_key_header') or 'x-api-key').strip() or 'x-api-key'
        api_key = (g.get('google_secops_gateway_api_key') or '').strip()
        if not api_key:
            raise ValueError('API Gateway API key value is empty')
        core = {header_name: api_key, 'Content-Type': 'application/json'}
    return session, _merge_custom_headers(core, g)


def _api_url(base: str, *path_segments: str) -> str:
    return base.rstrip('/') + '/' + '/'.join(path_segments)


def google_secops_push_ioc_from_context(ioc: dict[str, Any]) -> tuple[bool, str]:
    """
    Sync one IOC lifecycle event to Google SecOps Data Table (when configured).

    ``ioc`` is from ``ioc_context_from_submission``. Rows are two columns: type slug, value.
    """
    ok, msg = _google_secops_push_ioc_from_context_inner(ioc)
    try:
        from utils.integration_telemetry import record_vendor_push_attempt, record_vendor_push_if_applicable

        record_vendor_push_attempt('google_secops', data_kind='IOC', ok=ok, message=msg, count=1)
        record_vendor_push_if_applicable('google_secops', ok, msg)
    except Exception:
        pass
    return ok, msg


def _google_secops_push_ioc_from_context_inner(ioc: dict[str, Any]) -> tuple[bool, str]:
    if not google_secops_enabled():
        return True, 'disabled'
    if not isinstance(ioc, dict):
        return False, 'invalid_context'

    g = google_secops_settings_dict()
    parent = _data_table_parent(g)
    base = _api_rest_base(g)
    if not parent or not base:
        logger.warning(
            'Google SecOps outbound enabled but Data Table parent or API base incomplete '
            '(check connection mode, gateway/base host, project number, location, instance/customer id, data table id).'
        )
        return True, 'skipped_incomplete_data_table_config'

    verify_ssl = (g.get('google_secops_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')
    action = (str(ioc.get('action') or 'create')).strip().lower()
    ioc_type = (str(ioc.get('type') or '')).strip()
    value = (str(ioc.get('value') or '')).strip()
    if not value or not ioc_type:
        return False, 'missing_type_or_value'

    slug = _ioc_type_slug(ioc_type)

    try:
        session, headers = _build_request_session_and_headers(g, verify_ssl)
    except Exception as e:
        logger.exception('Google SecOps authentication failed')
        return False, str(e)[:240]

    if action == 'remove':
        return _delete_ioc_rows(session, base, parent, headers, slug, value)

    return _create_ioc_row(session, base, parent, headers, slug, value)


def _create_ioc_row(session, base: str, parent: str, headers: dict[str, str], slug: str, value: str) -> tuple[bool, str]:
    url = _api_url(base, API_VERSION, parent, 'dataTableRows:bulkCreate')
    body = {
        'requests': [
            {
                'parent': parent,
                'dataTableRow': {
                    'values': [slug, value],
                },
            },
        ],
    }
    try:
        r = session.post(url, headers=headers, json=body, timeout=REQUEST_TIMEOUT_SEC)
        msg = f'HTTP {r.status_code} bulkCreate'
        if r.status_code in (200, 201):
            return True, 'ok'
        try:
            detail = r.text[:500]
        except Exception:
            detail = ''
        logger.warning('Google SecOps bulkCreate failed: %s %s', msg, detail)
        return False, f'{msg} {detail}'.strip()
    except Exception as e:
        logger.exception('Google SecOps bulkCreate request failed')
        return False, str(e)[:240]


def _delete_ioc_rows(session, base: str, parent: str, headers: dict[str, str], slug: str, value: str) -> tuple[bool, str]:
    """List rows with filter on value, delete those matching type slug + value."""
    to_delete: list[str] = []
    page_token: Optional[str] = None
    list_root = _api_url(base, API_VERSION, parent, 'dataTableRows')

    while True:
        params: dict[str, Any] = {'pageSize': 1000, 'filter': value}
        if page_token:
            params['pageToken'] = page_token
        try:
            r = session.get(list_root, headers=headers, params=params, timeout=REQUEST_TIMEOUT_SEC)
        except Exception as e:
            logger.exception('Google SecOps dataTableRows.list failed')
            return False, str(e)[:240]
        if r.status_code != 200:
            logger.warning('Google SecOps list rows HTTP %s %s', r.status_code, r.text[:300])
            return False, f'list HTTP {r.status_code}'
        try:
            data = r.json()
        except json.JSONDecodeError:
            return False, 'list invalid JSON'
        for row in data.get('dataTableRows') or []:
            if isinstance(row, dict) and _row_matches_ioc(row, slug, value):
                name = (row.get('name') or '').strip()
                if name:
                    to_delete.append(name)
        page_token = data.get('nextPageToken') or None
        if not page_token:
            break

    if not to_delete:
        return True, 'remove_no_matching_rows'

    errors: list[str] = []
    for name in to_delete:
        del_url = _api_url(base, API_VERSION, name)
        try:
            dr = session.delete(del_url, headers=headers, timeout=REQUEST_TIMEOUT_SEC)
            if dr.status_code not in (200, 204):
                errors.append(f'{name}:{dr.status_code}')
        except Exception as e:
            errors.append(f'{name}:{str(e)[:80]}')

    if errors:
        return False, 'delete_partial ' + ';'.join(errors)[:240]
    return True, f'removed_{len(to_delete)}'


def _checklist_credentials_direct(settings: dict[str, str], steps: list[dict[str, str]]) -> None:
    raw = (settings.get('google_secops_credentials_json') or '').strip()
    if not raw:
        steps.append({'step': 'credentials', 'status': 'fail', 'message': 'Service account JSON is empty'})
    else:
        try:
            info = json.loads(raw)
            if not isinstance(info, dict):
                raise ValueError('JSON must be an object')
            email = (info.get('client_email') or '').strip() or 'unknown'
            if not (info.get('private_key') or '').strip():
                steps.append({
                    'step': 'credentials',
                    'status': 'fail',
                    'message': f'JSON parsed ({email}) but private_key is missing',
                })
            else:
                steps.append({'step': 'credentials', 'status': 'ok', 'message': f'JSON ok ({email})'})
        except (json.JSONDecodeError, ValueError) as e:
            steps.append({'step': 'credentials', 'status': 'fail', 'message': f'Invalid credentials JSON: {e}'})


def _checklist_gateway_auth(settings: dict[str, str], steps: list[dict[str, str]]) -> None:
    base = (settings.get('google_secops_gateway_base_url') or '').strip().rstrip('/')
    if base:
        steps.append({'step': 'gateway_base', 'status': 'ok', 'message': base})
    else:
        steps.append({'step': 'gateway_base', 'status': 'fail', 'message': 'API Gateway base URL not set'})

    auth = google_secops_gateway_auth_method(settings)
    if auth == GATEWAY_AUTH_OAUTH2:
        token_url = (settings.get('google_secops_gateway_oauth_token_url') or '').strip()
        cid = (settings.get('google_secops_gateway_oauth_client_id') or '').strip()
        secret = (settings.get('google_secops_gateway_oauth_client_secret') or '').strip()
        if token_url and cid and secret:
            steps.append({'step': 'gateway_auth', 'status': 'ok', 'message': 'OAuth2 client credentials configured'})
        else:
            missing = []
            if not token_url:
                missing.append('token URL')
            if not cid:
                missing.append('client ID')
            if not secret:
                missing.append('client secret')
            steps.append({
                'step': 'gateway_auth',
                'status': 'fail',
                'message': 'OAuth2 incomplete: ' + ', '.join(missing),
            })
    else:
        key = (settings.get('google_secops_gateway_api_key') or '').strip()
        hname = (settings.get('google_secops_gateway_api_key_header') or 'x-api-key').strip() or 'x-api-key'
        if key:
            steps.append({'step': 'gateway_auth', 'status': 'ok', 'message': f'API key header {hname!r} configured'})
        else:
            steps.append({'step': 'gateway_auth', 'status': 'fail', 'message': 'API key value not set'})

    custom = parse_google_secops_gateway_custom_headers(settings)
    if custom:
        steps.append({
            'step': 'gateway_custom_headers',
            'status': 'ok',
            'message': f'{len(custom)} custom header(s)',
        })
    else:
        steps.append({
            'step': 'gateway_custom_headers',
            'status': 'ok',
            'message': 'No custom headers (optional)',
        })


def google_secops_config_checklist(g: Optional[dict[str, str]] = None) -> list[dict[str, str]]:
    """
    Pre-flight configuration checks (no HTTP). Used by Admin diagnostics and CLI troubleshooting.
    """
    settings = g or google_secops_settings_dict()
    steps: list[dict[str, str]] = []
    mode = google_secops_connection_mode(settings)
    steps.append({
        'step': 'connection_mode',
        'status': 'ok',
        'message': 'API Gateway / Apigee' if mode == CONNECTION_MODE_APIGEE else 'Direct GCP service account',
    })

    if mode == CONNECTION_MODE_DIRECT:
        _checklist_credentials_direct(settings, steps)
    else:
        _checklist_gateway_auth(settings, steps)

    proj = (settings.get('google_secops_project_number') or '').strip()
    steps.append({
        'step': 'project_number',
        'status': 'ok' if proj else 'fail',
        'message': proj or 'GCP project number not set',
    })

    loc = (settings.get('google_secops_location') or '').strip()
    steps.append({
        'step': 'location',
        'status': 'ok' if loc else 'fail',
        'message': loc or 'Location (region) not set',
    })

    inst = (settings.get('google_secops_instance_id') or '').strip()
    cust = (settings.get('google_secops_customer_id') or '').strip()
    if inst or cust:
        steps.append({
            'step': 'instance',
            'status': 'ok',
            'message': f'instance id = {inst or cust}' + (' (customer_id fallback)' if not inst and cust else ''),
        })
    else:
        steps.append({'step': 'instance', 'status': 'fail', 'message': 'Set Customer ID (or Instance ID)'})

    tid = (settings.get('google_secops_data_table_id') or '').strip()
    steps.append({
        'step': 'data_table_id',
        'status': 'ok' if tid else 'fail',
        'message': tid or 'Data table ID not set',
    })

    api_base = _api_rest_base(settings)
    step_name = 'gateway_base' if mode == CONNECTION_MODE_APIGEE else 'chronicle_host'
    if api_base:
        if mode == CONNECTION_MODE_DIRECT and step_name == 'chronicle_host':
            steps.append({'step': 'chronicle_host', 'status': 'ok', 'message': api_base})
        elif mode == CONNECTION_MODE_APIGEE and not any(s['step'] == 'gateway_base' for s in steps):
            steps.append({'step': 'gateway_base', 'status': 'ok' if api_base else 'fail', 'message': api_base or 'missing'})
    else:
        if mode == CONNECTION_MODE_DIRECT:
            steps.append({
                'step': 'chronicle_host',
                'status': 'fail',
                'message': 'Set Location or Chronicle REST API host',
            })
        elif not any(s['step'] == 'gateway_base' for s in steps):
            steps.append({'step': 'gateway_base', 'status': 'fail', 'message': 'API Gateway base URL not set'})

    parent = _data_table_parent(settings)
    if parent:
        steps.append({'step': 'resource_path', 'status': 'ok', 'message': parent})
    else:
        steps.append({
            'step': 'resource_path',
            'status': 'fail',
            'message': 'Cannot build dataTables parent path (check project, location, instance, table id)',
        })

    if google_secops_enabled(settings):
        steps.append({'step': 'outbound_enabled', 'status': 'ok', 'message': 'Outbound push is enabled'})
    else:
        steps.append({
            'step': 'outbound_enabled',
            'status': 'warn',
            'message': 'Outbound disabled — IOC push runs only when Enable = Yes',
        })

    if mode == CONNECTION_MODE_DIRECT:
        ibase = _ingestion_api_base(settings)
        steps.append({
            'step': 'ingestion_host',
            'status': 'ok',
            'message': f'{ibase} (optional; used only for ingestion probe, not IOC push)',
        })

    return steps


def _config_ready_for_api(g: dict[str, str]) -> bool:
    """True when required Data Table + auth fields are present."""
    mode = google_secops_connection_mode(g)
    if mode == CONNECTION_MODE_DIRECT:
        required_ok = {
            'credentials', 'project_number', 'location', 'instance',
            'data_table_id', 'chronicle_host', 'resource_path',
        }
    else:
        required_ok = {
            'gateway_base', 'gateway_auth', 'project_number', 'location',
            'instance', 'data_table_id', 'resource_path',
        }
    by_step = {s['step']: s for s in google_secops_config_checklist(g)}
    for key in required_ok:
        if by_step.get(key, {}).get('status') != 'ok':
            return False
    return True


def _test_roundtrip_row(
    session,
    base: str,
    parent: str,
    headers: dict[str, str],
) -> tuple[bool, list[dict[str, str]]]:
    """
    Write one diagnostic domain row via bulkCreate, then list+delete it (production code paths).
    Uses a reserved .invalid hostname that should never be a real indicator.
    """
    steps: list[dict[str, str]] = []
    test_value = f'ziochub-diag-{secrets.token_hex(6)}.invalid'
    slug = 'domain'

    ok_create, msg_create = _create_ioc_row(session, base, parent, headers, slug, test_value)
    if ok_create:
        steps.append({
            'step': 'roundtrip_create',
            'status': 'ok',
            'message': f'bulkCreate ok ({test_value})',
        })
    else:
        steps.append({
            'step': 'roundtrip_create',
            'status': 'fail',
            'message': f'{msg_create} (IAM: chronicle.dataTableRows.bulkCreate)',
        })
        return False, steps

    ok_delete, msg_delete = _delete_ioc_rows(session, base, parent, headers, slug, test_value)
    if ok_delete:
        steps.append({
            'step': 'roundtrip_delete',
            'status': 'ok',
            'message': f'list+delete ok ({msg_delete})',
        })
        return True, steps

    steps.append({
        'step': 'roundtrip_delete',
        'status': 'fail',
        'message': f'{msg_delete} (IAM: chronicle.dataTableRows.list + .delete)',
    })
    return False, steps


def google_secops_test_connection(
    settings: Optional[dict[str, str]] = None,
    *,
    verify_ssl: Optional[bool] = None,
    roundtrip: bool = False,
    config_only: bool = False,
) -> dict[str, Any]:
    """
    Troubleshooting probe: config checklist, auth, Data Table GET, optional ingestion GET (direct only),
    optional bulkCreate+delete round-trip on the Data Table.
    """
    g = settings or google_secops_settings_dict()
    steps: list[dict[str, str]] = list(google_secops_config_checklist(g))
    mode = google_secops_connection_mode(g)

    if config_only:
        ok = _config_ready_for_api(g)
        return {'success': ok, 'steps': steps, 'config_only': True}

    if not _config_ready_for_api(g):
        return {'success': False, 'steps': steps}

    if verify_ssl is None:
        verify_ssl = (g.get('google_secops_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')

    try:
        session, headers = _build_request_session_and_headers(g, verify_ssl)
    except json.JSONDecodeError as e:
        steps.append({'step': 'auth', 'status': 'fail', 'message': str(e)})
        return {'success': False, 'steps': steps}
    except Exception as e:
        steps.append({'step': 'auth', 'status': 'fail', 'message': str(e)[:240]})
        return {'success': False, 'steps': steps}

    if mode == CONNECTION_MODE_DIRECT:
        steps.append({
            'step': 'auth',
            'status': 'ok',
            'message': 'GCP service account token issued (scopes: chronicle + malachite-ingestion)',
        })
    elif google_secops_gateway_auth_method(g) == GATEWAY_AUTH_OAUTH2:
        steps.append({'step': 'auth', 'status': 'ok', 'message': 'OAuth2 client-credentials token issued'})
    else:
        steps.append({'step': 'auth', 'status': 'ok', 'message': 'API key header configured for gateway'})

    parent = _data_table_parent(g)
    cbase = _api_rest_base(g)
    data_table_ok = False
    roundtrip_ok = False
    if parent and cbase:
        dt_url = _api_url(cbase, API_VERSION, parent)
        try:
            r = session.get(dt_url, headers=headers, timeout=REQUEST_TIMEOUT_SEC)
            msg = f'HTTP {r.status_code} GET dataTable'
            if r.status_code == 200:
                data_table_ok = True
                label = 'API Gateway' if mode == CONNECTION_MODE_APIGEE else 'Chronicle REST'
                steps.append({'step': 'data_table', 'status': 'ok', 'message': msg + f' ({label})'})
            elif r.status_code == 403:
                steps.append({
                    'step': 'data_table',
                    'status': 'fail',
                    'message': msg + ' (IAM: chronicle.dataTables.get on table resource)',
                })
                return {'success': False, 'steps': steps}
            else:
                steps.append({'step': 'data_table', 'status': 'fail', 'message': msg + ' ' + r.text[:200]})
                return {'success': False, 'steps': steps}
        except Exception as e:
            steps.append({'step': 'data_table', 'status': 'fail', 'message': str(e)[:240]})
            return {'success': False, 'steps': steps}

        if roundtrip and data_table_ok:
            roundtrip_ok, rt_steps = _test_roundtrip_row(session, cbase, parent, headers)
            steps.extend(rt_steps)
            if not roundtrip_ok:
                return {'success': False, 'steps': steps}
    else:
        steps.append({
            'step': 'data_table',
            'status': 'skipped',
            'message': 'skipped (incomplete Data Table config — see checklist above)',
        })

    ingestion_ok = False
    if mode == CONNECTION_MODE_DIRECT:
        ibase = _ingestion_api_base(g)
        probe_url = f'{ibase}/v2/logtypes'
        try:
            r = session.get(probe_url, headers=headers, timeout=REQUEST_TIMEOUT_SEC)
            msg = f'HTTP {r.status_code} GET {probe_url}'
            if r.status_code == 401:
                steps.append({'step': 'ingestion_api', 'status': 'fail', 'message': msg})
                if not data_table_ok:
                    return {'success': False, 'steps': steps}
            elif r.status_code == 403:
                ingestion_ok = True
                steps.append({
                    'step': 'ingestion_api',
                    'status': 'ok',
                    'message': msg + ' (403: ingestion restricted; IOC push uses Data Table only)',
                })
            elif r.status_code >= 500:
                steps.append({'step': 'ingestion_api', 'status': 'fail', 'message': msg})
                if not data_table_ok:
                    return {'success': False, 'steps': steps}
            elif r.status_code == 404:
                steps.append({
                    'step': 'ingestion_api',
                    'status': 'fail',
                    'message': msg + ' (wrong ingestion host for region?)',
                })
                if not data_table_ok:
                    return {'success': False, 'steps': steps}
            else:
                ingestion_ok = True
                steps.append({'step': 'ingestion_api', 'status': 'ok', 'message': msg + ' (Ingestion API reachable)'})
        except Exception as e:
            steps.append({'step': 'ingestion_api', 'status': 'fail', 'message': str(e)[:240]})
            if not data_table_ok:
                return {'success': False, 'steps': steps}
    else:
        steps.append({
            'step': 'ingestion_api',
            'status': 'skipped',
            'message': 'skipped (ingestion probe is direct-mode only)',
        })

    if roundtrip:
        return {'success': data_table_ok and roundtrip_ok, 'steps': steps}
    if mode == CONNECTION_MODE_APIGEE:
        return {'success': data_table_ok, 'steps': steps}
    return {'success': data_table_ok or ingestion_ok, 'steps': steps}
