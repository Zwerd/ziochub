"""
MISP integration settings – single source of truth for keys, defaults, and normalization.

Used by Admin Settings UI and by utils.misp_sync. Settings are stored in DB (SystemSetting);
this module defines which keys exist and their default values.
"""
from __future__ import annotations

# All MISP-related setting keys (stored in DB)
MISP_SETTING_KEYS = (
    'misp_enabled',
    'misp_url',
    'misp_api_key',
    'misp_verify_ssl',
    'misp_last_days',
    'misp_filter_tags',
    'misp_filter_types',
    'misp_published_only',
    'misp_default_ttl',
    'misp_sync_user',
    'misp_pull_interval',
    'misp_exclude_from_champs',
    'misp_last_sync',
    'misp_last_sync_result',
)

# Keys that can be saved from the admin form (excludes read-only last_sync, last_sync_result)
MISP_SAVE_KEYS = tuple(k for k in MISP_SETTING_KEYS if k not in ('misp_last_sync', 'misp_last_sync_result'))

# Keys required for sync (subset used by run_sync)
MISP_SYNC_KEYS = (
    'misp_url',
    'misp_api_key',
    'misp_verify_ssl',
    'misp_last_days',
    'misp_filter_tags',
    'misp_filter_types',
    'misp_published_only',
    'misp_default_ttl',
    'misp_sync_user',
)

# Default values for MISP settings
MISP_DEFAULTS = {
    'misp_enabled': 'false',
    'misp_url': '',
    'misp_api_key': '',
    'misp_verify_ssl': 'false',
    'misp_last_days': '30',
    'misp_filter_tags': '',
    'misp_filter_types': '',
    'misp_published_only': 'true',
    'misp_default_ttl': 'permanent',
    'misp_sync_user': 'misp_sync',
    'misp_pull_interval': '60',
    'misp_exclude_from_champs': 'true',
    'misp_last_sync': '',
    'misp_last_sync_result': '',
}


def get_settings_for_form(get_setting_fn) -> dict:
    """
    Build a dict of MISP settings for the admin form.
    get_setting_fn(key) or get_setting_fn(key, default) should return the stored value.
    """
    out = {}
    for key in MISP_SETTING_KEYS:
        default = MISP_DEFAULTS.get(key, '')
        out[key] = (get_setting_fn(key, default) if callable(get_setting_fn) else get_setting_fn.get(key, default))
        if out[key] is None:
            out[key] = default
        out[key] = str(out[key]).strip() if out[key] else default
    return out


def normalize_sync_settings(settings: dict) -> dict:
    """
    Normalize a raw settings dict for run_sync: apply defaults, coerce types.
    Returns a dict with only the keys needed for sync, with consistent types.
    """
    normalized = {}
    for key in MISP_SYNC_KEYS:
        raw = settings.get(key)
        default = MISP_DEFAULTS.get(key, '')
        val = str(raw).strip() if raw is not None and str(raw).strip() else default
        normalized[key] = val

    # Coerce last_days to int
    try:
        normalized['misp_last_days'] = str(max(1, min(365, int(normalized['misp_last_days'] or '30'))))
    except (ValueError, TypeError):
        normalized['misp_last_days'] = '30'

    return normalized
