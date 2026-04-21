"""
Google Security Operations (SecOps, Chronicle) — IOC outbound via **Data Table** REST API.

- **Ingestion API** (malachite-ingestion, ``GET /v2/logtypes``): optional connectivity check; host in
  ``google_secops_base_url``.
- **Data Tables** (Chronicle REST ``v1beta``): IOC create/remove uses ``dataTableRows:bulkCreate`` and
  ``dataTableRows.list`` + ``delete``. Requires OAuth scope ``https://www.googleapis.com/auth/chronicle``
  (or cloud-platform) and IAM such as ``chronicle.dataTableRows.bulkCreate``.

Docs:
- Ingestion: https://docs.cloud.google.com/chronicle/docs/reference/ingestion-api
- Data tables REST: https://docs.cloud.google.com/chronicle/docs/reference/rest/v1beta/projects.locations.instances.dataTables.dataTableRows/bulkCreate
- REST endpoints: https://docs.cloud.google.com/chronicle/docs/reference/rest#rest_endpoints

**Table shape:** two string columns in order: (1) IOC type slug, (2) IOC value — e.g. ``["domain", "example.com"]``.
Admin must create this table in SecOps and set **Data table ID** (resource id, e.g. ``iocs_table``) plus
project number, location, instance, and Chronicle API host (or location for default host).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SEC = 90

MALACHITE_INGESTION_SCOPE = 'https://www.googleapis.com/auth/malachite-ingestion'
CHRONICLE_SCOPE = 'https://www.googleapis.com/auth/chronicle'
DEFAULT_INGESTION_HOST_US = 'https://malachiteingestion-pa.googleapis.com'

API_VERSION = 'v1beta'

_SCOPES = (CHRONICLE_SCOPE, MALACHITE_INGESTION_SCOPE)


def _get_setting(key: str, default: str = '') -> str:
    import app as _app
    return _app._get_setting(key, default)


def google_secops_enabled(settings: Optional[dict[str, str]] = None) -> bool:
    g = settings or google_secops_settings_dict()
    return (g.get('google_secops_enabled', 'false') or 'false').strip().lower() in ('true', '1', 'yes')


def google_secops_settings_dict() -> dict[str, str]:
    keys = (
        'google_secops_enabled',
        'google_secops_base_url',
        'google_secops_chronicle_api_base',
        'google_secops_project_number',
        'google_secops_location',
        'google_secops_instance_id',
        'google_secops_customer_id',
        'google_secops_data_table_id',
        'google_secops_credentials_json',
        'google_secops_verify_ssl',
    )
    return {k: _get_setting(k, '') for k in keys}


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
    base = _chronicle_rest_base(g)
    if not parent or not base:
        logger.warning(
            'Google SecOps outbound enabled but Data Table parent incomplete '
            '(need project number, location, instance or customer_id, data table id, and Chronicle API host or location).'
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
        creds, session = _load_credentials(g, verify_ssl)
    except Exception as e:
        logger.exception('Google SecOps OAuth/credentials failed')
        return False, str(e)[:240]

    headers = {'Authorization': f'Bearer {creds.token}', 'Content-Type': 'application/json'}

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


def google_secops_test_connection(
    settings: Optional[dict[str, str]] = None,
    *,
    verify_ssl: Optional[bool] = None,
) -> dict[str, Any]:
    """
    OAuth with chronicle + malachite-ingestion scopes; optionally GET Data Table metadata;
    optionally GET Ingestion ``/v2/logtypes``.
    """
    g = settings or google_secops_settings_dict()
    steps: list[dict[str, str]] = []

    raw = (g.get('google_secops_credentials_json') or '').strip()
    if not raw:
        steps.append({'step': 'config', 'status': 'fail', 'message': 'google_secops_credentials_json is empty'})
        return {'success': False, 'steps': steps}

    if verify_ssl is None:
        verify_ssl = (g.get('google_secops_verify_ssl', 'true') or 'true').strip().lower() in ('true', '1', 'yes')

    try:
        creds, session = _load_credentials(g, verify_ssl)
    except json.JSONDecodeError as e:
        steps.append({'step': 'json', 'status': 'fail', 'message': str(e)})
        return {'success': False, 'steps': steps}
    except Exception as e:
        steps.append({'step': 'oauth', 'status': 'fail', 'message': str(e)[:240]})
        return {'success': False, 'steps': steps}

    steps.append({
        'step': 'oauth',
        'status': 'ok',
        'message': 'Access token issued (chronicle + malachite-ingestion)',
    })

    headers = {'Authorization': f'Bearer {creds.token}'}

    parent = _data_table_parent(g)
    cbase = _chronicle_rest_base(g)
    data_table_ok = False
    if parent and cbase:
        dt_url = _api_url(cbase, API_VERSION, parent)
        try:
            r = session.get(dt_url, headers=headers, timeout=REQUEST_TIMEOUT_SEC)
            msg = f'HTTP {r.status_code} GET dataTable'
            if r.status_code == 200:
                data_table_ok = True
                steps.append({'step': 'data_table', 'status': 'ok', 'message': msg + ' (Chronicle REST)'})
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
    else:
        steps.append({
            'step': 'data_table',
            'status': 'skipped',
            'message': 'skipped (set Chronicle API host or location, project #, location, table id, instance or customer_id)',
        })

    ibase = _ingestion_api_base(g)
    probe_url = f'{ibase}/v2/logtypes'
    ingestion_ok = False
    try:
        r = session.get(probe_url, headers=headers, timeout=REQUEST_TIMEOUT_SEC)
        msg = f'HTTP {r.status_code} GET {probe_url}'
        if r.status_code == 401:
            steps.append({'step': 'ingestion_api', 'status': 'fail', 'message': msg})
            return {'success': False, 'steps': steps}
        if r.status_code == 403:
            ingestion_ok = True
            steps.append({
                'step': 'ingestion_api',
                'status': 'ok',
                'message': msg + ' (403: ingestion may still be restricted; Data Table uses Chronicle scope)',
            })
        elif r.status_code >= 500:
            steps.append({'step': 'ingestion_api', 'status': 'fail', 'message': msg})
            if not data_table_ok:
                return {'success': False, 'steps': steps}
        elif r.status_code == 404:
            steps.append({
                'step': 'ingestion_api',
                'status': 'fail',
                'message': msg + ' (wrong ingestion host for region)',
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

    return {'success': data_table_ok or ingestion_ok, 'steps': steps}
