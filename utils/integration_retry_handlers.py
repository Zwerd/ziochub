"""Per-vendor push handlers for scheduled integration retry."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def dispatch_integration_retry_push(
    vendor: str,
    payload: dict[str, Any],
    *,
    from_retry: bool = True,
) -> tuple[bool, str]:
    import app as _app

    get_setting = _app._get_setting
    if vendor == 'cortex_xdr':
        from utils.cortex_xdr import cortex_xdr_push_ioc_from_context
        return cortex_xdr_push_ioc_from_context(payload, from_retry=from_retry)
    if vendor == 'google_secops':
        from utils.google_secops import google_secops_push_ioc_from_context
        return google_secops_push_ioc_from_context(payload, from_retry=from_retry)
    if vendor == 'esa':
        return _retry_esa(payload, get_setting)
    if vendor == 'ioc_http':
        return _retry_ioc_http(payload, get_setting)
    if vendor == 'misp_push':
        return _retry_misp_push(payload, get_setting)
    if vendor == 'dxl':
        return _retry_dxl(payload, get_setting)
    if vendor in ('yara_http', 'trellix_ex', 'trellix_cms', 'trellix_nx'):
        return _retry_yara_vendor(vendor, payload, get_setting)
    return False, f'unknown_vendor:{vendor}'


def _retry_esa(payload: dict[str, Any], get_setting) -> tuple[bool, str]:
    from collections import defaultdict

    from utils.cisco_esa import (
        dictionary_names_for_ioc_type,
        esa_push_add_by_dictionary,
        esa_push_remove_by_dictionary,
        esa_settings_dict,
        normalize_dictionary_word,
        parse_mappings,
    )

    ioc_type = (str(payload.get('type') or payload.get('ioc_type') or '')).strip()
    value = (str(payload.get('value') or '')).strip()
    action = (str(payload.get('action') or 'create')).strip().lower()
    if not ioc_type or not value:
        return False, 'missing_type_or_value'
    g = esa_settings_dict()
    word = normalize_dictionary_word(ioc_type, value)
    if not word:
        return False, 'empty_word'
    mappings = parse_mappings(g.get('esa_mappings', '[]'))
    by_dict: dict[str, set[str]] = defaultdict(set)
    for dname in dictionary_names_for_ioc_type(mappings, ioc_type):
        by_dict[dname].add(word)
    if not by_dict:
        return True, 'no_dictionary_mapping'
    if action in ('remove', 'delete', 'revoke', 'expire_remove', 'delete_remove'):
        return esa_push_remove_by_dictionary(by_dict, settings=g, audit_log_fn=None)
    return esa_push_add_by_dictionary(by_dict, settings=g, audit_log_fn=None)


def _retry_ioc_http(payload: dict[str, Any], get_setting) -> tuple[bool, str]:
    from utils.ioc_push import load_targets, push_one_ioc_to_all_targets

    if (get_setting('ioc_push_enabled', 'false') or '').strip().lower() not in ('true', '1', 'yes'):
        return True, 'disabled'
    res = push_one_ioc_to_all_targets(payload, audit_log_fn=None)
    ok = bool(res.get('overall_success'))
    if ok:
        return True, 'ioc_http_ok'
    msgs = '; '.join(
        (r.get('name') or '') + ': ' + (r.get('message') or '')
        for r in (res.get('results') or [])
        if not r.get('success')
    )
    return False, (msgs or 'ioc_http_failed')[:240]


def _retry_misp_push(payload: dict[str, Any], get_setting) -> tuple[bool, str]:
    from utils.misp_push import push_ioc_to_misp

    ioc_type = (str(payload.get('type') or '')).strip()
    value = (str(payload.get('value') or '')).strip()
    url = (get_setting('misp_url', '') or '').strip()
    api_key = (get_setting('misp_api_key', '') or '').strip()
    if not url or not api_key:
        return False, 'missing_config'
    verify_ssl = (get_setting('misp_verify_ssl', 'false') or '').strip().lower() in ('true', '1', 'yes')
    include_comment = (get_setting('misp_push_include_comment', 'true') or '').strip().lower() in ('true', '1', 'yes')
    event_id_str = (get_setting('misp_push_default_event_id', '') or '').strip()
    event_id = int(event_id_str) if event_id_str.isdigit() else None
    comment = payload.get('comment')
    return push_ioc_to_misp(
        ioc_type, value, comment,
        event_id=event_id, url=url, api_key=api_key,
        verify_ssl=verify_ssl, include_comment=include_comment,
        from_retry=from_retry,
    )


def _retry_dxl(payload: dict[str, Any], get_setting) -> tuple[bool, str]:
    from utils.dxl_tie import push_hash_to_tie

    if (get_setting('dxl_enabled', 'false') or '').strip().lower() not in ('true', '1', 'yes'):
        return True, 'disabled'
    config_path = (get_setting('dxl_config_path', '') or '').strip()
    value = (str(payload.get('value') or '')).strip()
    if not config_path:
        return False, 'missing_config'
    ok = push_hash_to_tie(config_path, value, audit_log_fn=None)
    return (ok, 'dxl_ok' if ok else 'dxl_push_failed')


def _yara_file_content(filename: str) -> tuple[bool, str, str]:
    import app as _app

    data_yara = _app.app.config.get('DATA_YARA') or ''
    path = os.path.join(data_yara, filename)
    if not os.path.isfile(path):
        return False, '', 'yara_file_not_found'
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return True, f.read(), 'ok'


def _retry_yara_vendor(vendor: str, payload: dict[str, Any], get_setting) -> tuple[bool, str]:
    kind = (str(payload.get('kind') or 'push')).strip().lower()
    filename = (str(payload.get('filename') or '')).strip()
    if not filename:
        return False, 'missing_filename'

    if kind == 'delete':
        return _retry_yara_delete(vendor, filename, get_setting)

    ok_read, content, read_msg = _yara_file_content(filename)
    if not ok_read:
        return False, read_msg

    from utils.yara_push_targets import yara_http_push_verify_ssl, yara_session_push_verify_ssl

    verify_http = yara_http_push_verify_ssl(get_setting)
    verify_session = yara_session_push_verify_ssl(get_setting)

    if vendor == 'yara_http':
        from utils.yara_push_targets import merged_yara_automation_appliances
        from utils.yara_http_push import push_yara_to_appliances

        if (get_setting('automation_fireeye_enabled', 'false') or '').strip().lower() not in ('true', '1', 'yes'):
            return True, 'disabled'
        appliances = merged_yara_automation_appliances(get_setting)
        if not appliances:
            return False, 'no_targets'
        res = push_yara_to_appliances(content, filename, appliances, None, verify_ssl=verify_http)
        try:
            from utils.downstream import record_yara_push_target_results, yara_api_source_for_vendor
            record_yara_push_target_results(
                filename, res.get('results', []), api_source=yara_api_source_for_vendor(vendor),
            )
        except Exception:
            pass
        ok = bool(res.get('overall_success'))
        if ok:
            return True, 'yara_http_ok'
        msg = '; '.join(
            (r.get('name') or '') + ': ' + (r.get('message') or '')
            for r in (res.get('results') or [])
            if not r.get('success')
        )
        return False, (msg or 'yara_http_failed')[:240]

    if vendor == 'trellix_ex':
        from utils.trellix_ex import push_yara_trellix_ex, trellix_ex_enabled
        if not trellix_ex_enabled(get_setting):
            return True, 'disabled'
        res = push_yara_trellix_ex(content, filename, get_setting, None, verify_ssl=verify_session)
    elif vendor == 'trellix_cms':
        from utils.trellix_cms import push_yara_trellix_cms, trellix_cms_enabled
        if not trellix_cms_enabled(get_setting):
            return True, 'disabled'
        res = push_yara_trellix_cms(content, filename, get_setting, None, verify_ssl=verify_session)
    elif vendor == 'trellix_nx':
        from utils.trellix_nx import push_yara_nx_wmps, trellix_nx_wmps_enabled
        if not trellix_nx_wmps_enabled(get_setting):
            return True, 'disabled'
        res = push_yara_nx_wmps(content, filename, get_setting, None, verify_ssl=verify_session)
    else:
        return False, 'unknown_yara_vendor'

    try:
        from utils.downstream import record_yara_push_target_results, yara_api_source_for_vendor
        record_yara_push_target_results(
            filename, res.get('results', []), api_source=yara_api_source_for_vendor(vendor),
        )
    except Exception:
        pass
    ok = bool(res.get('overall_success'))
    if ok:
        return True, f'{vendor}_ok'
    msg = '; '.join(
        (r.get('name') or '') + ': ' + (r.get('message') or '')
        for r in (res.get('results') or [])
        if not r.get('success')
    )
    return False, (msg or f'{vendor}_failed')[:240]


def _retry_yara_delete(vendor: str, filename: str, get_setting) -> tuple[bool, str]:
    from utils.yara_push_targets import yara_http_push_verify_ssl, yara_session_push_verify_ssl

    verify_http = yara_http_push_verify_ssl(get_setting)
    verify_session = yara_session_push_verify_ssl(get_setting)

    if vendor == 'yara_http':
        from utils.yara_push_targets import merged_yara_automation_appliances
        from utils.yara_http_push import delete_yara_from_appliances

        if (get_setting('automation_fireeye_enabled', 'false') or '').strip().lower() not in ('true', '1', 'yes'):
            return True, 'disabled'
        appliances = merged_yara_automation_appliances(get_setting)
        if not appliances:
            return False, 'no_targets'
        res = delete_yara_from_appliances(filename, appliances, None, verify_ssl=verify_http)
    elif vendor == 'trellix_ex':
        from utils.trellix_ex import delete_yara_trellix_ex, trellix_ex_enabled
        if not trellix_ex_enabled(get_setting):
            return True, 'disabled'
        res = delete_yara_trellix_ex(filename, get_setting, None, verify_ssl=verify_session)
    elif vendor == 'trellix_cms':
        from utils.trellix_cms import delete_yara_trellix_cms, trellix_cms_enabled
        if not trellix_cms_enabled(get_setting):
            return True, 'disabled'
        res = delete_yara_trellix_cms(filename, get_setting, None, verify_ssl=verify_session)
    elif vendor == 'trellix_nx':
        from utils.trellix_nx import delete_yara_nx_wmps, trellix_nx_wmps_enabled
        if not trellix_nx_wmps_enabled(get_setting):
            return True, 'disabled'
        res = delete_yara_nx_wmps(filename, get_setting, None, verify_ssl=verify_session)
    else:
        return False, 'unknown_yara_vendor'

    try:
        from utils.downstream import mark_yara_push_target_results_removed, yara_api_source_for_vendor
        mark_yara_push_target_results_removed(
            filename, res.get('results', []), api_source=yara_api_source_for_vendor(vendor),
        )
    except Exception:
        pass
    ok = bool(res.get('overall_success'))
    if ok:
        return True, f'{vendor}_delete_ok'
    msg = '; '.join(
        (r.get('name') or '') + ': ' + (r.get('message') or '')
        for r in (res.get('results') or [])
        if not r.get('success')
    )
    return False, (msg or f'{vendor}_delete_failed')[:240]
