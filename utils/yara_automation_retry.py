"""
Retry failed YARA automation targets (POST after approve, DELETE after rule removal).
Mirrors utils/ioc_push_retry for outbound IOC.
"""

from __future__ import annotations

import json
from typing import Callable, Tuple

from utils.yara_http_push import appliance_delete_url, appliance_upload_url, delete_yara_from_appliances, push_yara_to_appliances


class RetryError(Exception):
    """Base error for retry flow."""


class NoRecordedContextError(RetryError):
    """No stored context/results exist yet."""


class InvalidStoredContextError(RetryError):
    """Stored context exists but is invalid/unusable."""


class NoMatchingTargetsError(RetryError):
    """Targets list does not contain stored failed URLs."""


def retry_last_failed_yara_automation(
    *,
    kind: str,
    get_setting: Callable[[str, str], str],
    data_yara_dir: str,
    audit_log_fn=None,
) -> Tuple[dict, str]:
    """
    Retry failed YARA automation targets from the last recorded attempt.

    kind: 'push' | 'delete'
    data_yara_dir: approved YARA directory (for push: re-read file from disk).
    """
    kind_l = (kind or '').strip().lower()
    if kind_l not in ('push', 'delete'):
        raise ValueError('Invalid kind')

    from utils.integration_telemetry import (
        KEY_YARA_AUTOMATION_DELETE_CONTEXT,
        KEY_YARA_AUTOMATION_DELETE_RESULTS,
        KEY_YARA_AUTOMATION_PUSH_CONTEXT,
        KEY_YARA_AUTOMATION_PUSH_RESULTS,
        record_yara_automation_results,
    )

    if kind_l == 'delete':
        k_res, k_ctx = KEY_YARA_AUTOMATION_DELETE_RESULTS, KEY_YARA_AUTOMATION_DELETE_CONTEXT
    else:
        k_res, k_ctx = KEY_YARA_AUTOMATION_PUSH_RESULTS, KEY_YARA_AUTOMATION_PUSH_CONTEXT

    raw_res = (get_setting(k_res, '') or '').strip()
    raw_ctx = (get_setting(k_ctx, '') or '').strip()
    if not raw_res or not raw_ctx:
        raise NoRecordedContextError('No recorded YARA automation context/results to retry yet.')

    try:
        last = json.loads(raw_res)
    except Exception:
        last = {}
    try:
        ctx = json.loads(raw_ctx)
    except Exception:
        ctx = {}
    if not isinstance(ctx, dict) or not ctx:
        raise InvalidStoredContextError('Invalid stored context')

    filename = (ctx.get('filename') or '').strip()
    if not filename:
        raise InvalidStoredContextError('Missing filename in context')

    failed_urls = set()
    for r in (last.get('results') or []):
        try:
            if not r.get('success'):
                u = (r.get('url') or '').strip()
                if u:
                    failed_urls.add(u)
        except Exception:
            continue

    if not failed_urls:
        return {'retried': 0, 'results': last.get('results') or []}, 'No failed targets to retry.'

    from utils.trellix_ex import (
        delete_yara_trellix_ex,
        list_trellix_ex_delete_urls,
        list_trellix_ex_upload_urls,
        push_yara_trellix_ex,
        trellix_ex_enabled,
    )
    from utils.trellix_nx import (
        delete_yara_nx_wmps,
        list_nx_wmps_delete_urls,
        list_nx_wmps_upload_urls,
        push_yara_nx_wmps,
        trellix_nx_wmps_enabled,
    )
    from utils.yara_push_targets import merged_yara_automation_appliances
    appliances = merged_yara_automation_appliances(get_setting)
    if not isinstance(appliances, list):
        appliances = []

    targets = []
    for app in appliances:
        if not isinstance(app, dict):
            continue
        if kind_l == 'delete':
            u = appliance_delete_url(app, filename)
        else:
            u = appliance_upload_url(app)
        if u and u in failed_urls:
            targets.append(app)

    needs_trellix = False
    if kind_l == 'push' and trellix_ex_enabled(get_setting):
        for tu in list_trellix_ex_upload_urls(get_setting):
            if (tu or '').strip() and (tu or '').strip() in failed_urls:
                needs_trellix = True
                break
    if kind_l == 'delete' and trellix_ex_enabled(get_setting):
        for tu in list_trellix_ex_delete_urls(get_setting):
            if (tu or '').strip() and (tu or '').strip() in failed_urls:
                needs_trellix = True
                break

    needs_nx_wmps = False
    if kind_l == 'push' and trellix_nx_wmps_enabled(get_setting):
        for tu in list_nx_wmps_upload_urls(get_setting):
            if (tu or '').strip() and (tu or '').strip() in failed_urls:
                needs_nx_wmps = True
                break
    if kind_l == 'delete' and trellix_nx_wmps_enabled(get_setting):
        for tu in list_nx_wmps_delete_urls(get_setting):
            if (tu or '').strip() and (tu or '').strip() in failed_urls:
                needs_nx_wmps = True
                break

    if not targets and not needs_trellix and not needs_nx_wmps:
        raise NoMatchingTargetsError('No matching targets found (URLs changed?)')

    verify_ssl = (get_setting('automation_fireeye_ignore_ssl', 'false') or 'false').lower() != 'true'
    verify_tx = (get_setting('trellix_ex_verify_ssl', 'true') or 'true').lower() in ('true', '1', 'yes')

    if kind_l == 'delete':
        if targets:
            res = delete_yara_from_appliances(filename, targets, audit_log_fn, verify_ssl=verify_ssl)
        else:
            res = {'overall_success': True, 'results': []}
        if needs_trellix:
            res_tx = delete_yara_trellix_ex(filename, get_setting, audit_log_fn, verify_ssl=verify_tx)
            res = {
                'overall_success': bool(res.get('overall_success')) and bool(res_tx.get('overall_success')),
                'results': (res.get('results') or []) + (res_tx.get('results') or []),
            }
        if needs_nx_wmps:
            res_nx = delete_yara_nx_wmps(filename, get_setting, audit_log_fn, verify_ssl=None)
            res = {
                'overall_success': bool(res.get('overall_success')) and bool(res_nx.get('overall_success')),
                'results': (res.get('results') or []) + (res_nx.get('results') or []),
            }
    else:
        import os

        path = os.path.join(data_yara_dir or '', filename)
        if not os.path.isfile(path):
            raise InvalidStoredContextError('Approved YARA file not found for retry')
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        combined_results = []
        overall = True
        if targets:
            res_fe = push_yara_to_appliances(content, filename, targets, audit_log_fn, verify_ssl=verify_ssl)
            combined_results.extend(res_fe.get('results', []))
            overall = overall and bool(res_fe.get('overall_success'))
        if needs_trellix:
            res_tx = push_yara_trellix_ex(
                content, filename, get_setting, audit_log_fn, verify_ssl=verify_tx
            )
            combined_results.extend(res_tx.get('results', []))
            overall = overall and bool(res_tx.get('overall_success'))
        if needs_nx_wmps:
            res_nx = push_yara_nx_wmps(content, filename, get_setting, audit_log_fn, verify_ssl=None)
            combined_results.extend(res_nx.get('results', []))
            overall = overall and bool(res_nx.get('overall_success'))
        res = {'overall_success': overall, 'results': combined_results}

    record_yara_automation_results(res, kind=kind_l, context=ctx)
    return {'retried': len(targets), **res}, 'Retry completed'
