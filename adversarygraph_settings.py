"""
AdversaryGraph inbound pull settings (IOC Library + Detection Studio YARA).
"""
from __future__ import annotations

from utils.ioc_import_mode import DEFAULT_INTEGRATION_IOC_MODE, normalize_ioc_import_mode

ADVERSARYGRAPH_SETTING_KEYS = (
    'adversarygraph_enabled',
    'adversarygraph_url',
    'adversarygraph_verify_ssl',
    'adversarygraph_auth_user',
    'adversarygraph_auth_roles',
    'adversarygraph_last_days',
    'adversarygraph_filter_types',
    'adversarygraph_filter_sources',
    'adversarygraph_filter_actors',
    'adversarygraph_min_confidence',
    'adversarygraph_ioc_import_mode',
    'adversarygraph_yara_import_mode',
    'adversarygraph_pull_yara',
    'adversarygraph_sync_user',
    'adversarygraph_pull_interval',
    'adversarygraph_exclude_from_champs',
    'adversarygraph_default_ttl',
    'adversarygraph_last_sync',
    'adversarygraph_last_sync_result',
)

ADVERSARYGRAPH_SAVE_KEYS = tuple(
    k for k in ADVERSARYGRAPH_SETTING_KEYS if k not in ('adversarygraph_last_sync', 'adversarygraph_last_sync_result')
)

ADVERSARYGRAPH_SYNC_KEYS = (
    'adversarygraph_url',
    'adversarygraph_verify_ssl',
    'adversarygraph_auth_user',
    'adversarygraph_auth_roles',
    'adversarygraph_last_days',
    'adversarygraph_filter_types',
    'adversarygraph_filter_sources',
    'adversarygraph_filter_actors',
    'adversarygraph_min_confidence',
    'adversarygraph_ioc_import_mode',
    'adversarygraph_yara_import_mode',
    'adversarygraph_pull_yara',
    'adversarygraph_default_ttl',
    'adversarygraph_sync_user',
)

ADVERSARYGRAPH_DEFAULTS = {
    'adversarygraph_enabled': 'false',
    'adversarygraph_url': '',
    'adversarygraph_verify_ssl': 'false',
    'adversarygraph_auth_user': '',
    'adversarygraph_auth_roles': 'analyst',
    'adversarygraph_last_days': '30',
    'adversarygraph_filter_types': '',
    'adversarygraph_filter_sources': '',
    'adversarygraph_filter_actors': '',
    'adversarygraph_min_confidence': '0',
    'adversarygraph_ioc_import_mode': DEFAULT_INTEGRATION_IOC_MODE,
    'adversarygraph_yara_import_mode': DEFAULT_INTEGRATION_IOC_MODE,
    'adversarygraph_pull_yara': 'true',
    'adversarygraph_sync_user': 'adversarygraph_sync',
    'adversarygraph_pull_interval': '60',
    'adversarygraph_exclude_from_champs': 'true',
    'adversarygraph_default_ttl': 'permanent',
    'adversarygraph_last_sync': '',
    'adversarygraph_last_sync_result': '',
}


def normalize_import_mode(raw, default: str = DEFAULT_INTEGRATION_IOC_MODE) -> str:
    """Normalize AdversaryGraph import policy: auto | pending | block."""
    return normalize_ioc_import_mode(raw, default)


def get_settings_for_form(get_setting_fn) -> dict:
    out = {}
    for key in ADVERSARYGRAPH_SETTING_KEYS:
        default = ADVERSARYGRAPH_DEFAULTS.get(key, '')
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
    for key in ADVERSARYGRAPH_SYNC_KEYS:
        raw = settings.get(key)
        default = ADVERSARYGRAPH_DEFAULTS.get(key, '')
        val = str(raw).strip() if raw is not None and str(raw).strip() else default
        normalized[key] = val
    try:
        normalized['adversarygraph_last_days'] = str(
            max(1, min(365, int(normalized.get('adversarygraph_last_days') or '30')))
        )
    except (ValueError, TypeError):
        normalized['adversarygraph_last_days'] = '30'
    try:
        normalized['adversarygraph_min_confidence'] = str(
            max(0, min(100, int(normalized.get('adversarygraph_min_confidence') or '0')))
        )
    except (ValueError, TypeError):
        normalized['adversarygraph_min_confidence'] = '0'
    normalized['adversarygraph_ioc_import_mode'] = normalize_import_mode(
        normalized.get('adversarygraph_ioc_import_mode'), DEFAULT_INTEGRATION_IOC_MODE
    )
    normalized['adversarygraph_yara_import_mode'] = normalize_import_mode(
        normalized.get('adversarygraph_yara_import_mode'), DEFAULT_INTEGRATION_IOC_MODE
    )
    return normalized
