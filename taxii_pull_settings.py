"""
TAXII 2.1 inbound pull settings – keys, defaults, normalization (mirror misp_settings.py).
"""
from __future__ import annotations

from utils.ioc_import_mode import DEFAULT_INTEGRATION_IOC_MODE, normalize_ioc_import_mode

TAXII_SETTING_KEYS = (
    'taxii_pull_enabled',
    'taxii_discovery_url',
    'taxii_api_root_id',
    'taxii_collection_id',
    'taxii_username',
    'taxii_password',
    'taxii_api_key',
    'taxii_verify_ssl',
    'taxii_last_days',
    'taxii_pull_interval',
    'taxii_sync_user',
    'taxii_exclude_from_champs',
    'taxii_skip_revoked',
    'taxii_default_ttl',
    'taxii_ioc_import_mode',
    'taxii_last_sync',
    'taxii_last_sync_result',
)

TAXII_SAVE_KEYS = tuple(
    k for k in TAXII_SETTING_KEYS if k not in ('taxii_last_sync', 'taxii_last_sync_result')
)

TAXII_SYNC_KEYS = (
    'taxii_discovery_url',
    'taxii_api_root_id',
    'taxii_collection_id',
    'taxii_username',
    'taxii_password',
    'taxii_api_key',
    'taxii_verify_ssl',
    'taxii_last_days',
    'taxii_default_ttl',
    'taxii_sync_user',
    'taxii_skip_revoked',
    'taxii_ioc_import_mode',
)

TAXII_DEFAULTS = {
    'taxii_pull_enabled': 'false',
    'taxii_discovery_url': '',
    'taxii_api_root_id': '',
    'taxii_collection_id': '',
    'taxii_username': '',
    'taxii_password': '',
    'taxii_api_key': '',
    'taxii_verify_ssl': 'false',
    'taxii_last_days': '30',
    'taxii_pull_interval': '60',
    'taxii_sync_user': 'taxii_sync',
    'taxii_exclude_from_champs': 'true',
    'taxii_skip_revoked': 'true',
    'taxii_default_ttl': 'permanent',
    'taxii_ioc_import_mode': DEFAULT_INTEGRATION_IOC_MODE,
    'taxii_last_sync': '',
    'taxii_last_sync_result': '',
}


def get_settings_for_form(get_setting_fn) -> dict:
    out = {}
    for key in TAXII_SETTING_KEYS:
        default = TAXII_DEFAULTS.get(key, '')
        out[key] = (
            get_setting_fn(key, default)
            if callable(get_setting_fn)
            else get_setting_fn.get(key, default)
        )
        if out[key] is None:
            out[key] = default
        out[key] = str(out[key]).strip() if out[key] else default
    return out


def normalize_sync_settings(settings: dict) -> dict:
    normalized = {}
    for key in TAXII_SYNC_KEYS:
        raw = settings.get(key)
        default = TAXII_DEFAULTS.get(key, '')
        val = str(raw).strip() if raw is not None and str(raw).strip() else default
        normalized[key] = val
    try:
        normalized['taxii_last_days'] = str(max(1, min(365, int(normalized.get('taxii_last_days') or '30'))))
    except (ValueError, TypeError):
        normalized['taxii_last_days'] = '30'
    normalized['taxii_ioc_import_mode'] = normalize_ioc_import_mode(
        normalized.get('taxii_ioc_import_mode'), DEFAULT_INTEGRATION_IOC_MODE
    )
    return normalized
