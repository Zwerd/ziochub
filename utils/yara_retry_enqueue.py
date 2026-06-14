"""Enqueue failed YARA outbound pushes for scheduled retry."""

from __future__ import annotations

from typing import Any, Callable


def enqueue_yara_vendor_failure(
    vendor: str,
    filename: str,
    result: dict[str, Any],
    *,
    kind: str = 'push',
    get_setting: Callable[[str, str], str],
) -> None:
    if not filename or not isinstance(result, dict):
        return
    if result.get('overall_success'):
        return
    msg = '; '.join(
        (r.get('name') or '') + ': ' + (r.get('message') or '')
        for r in (result.get('results') or [])
        if not r.get('success')
    ) or 'yara_push_failed'
    try:
        from utils.integration_retry import enqueue_integration_retry, integration_is_retriable_failure

        if integration_is_retriable_failure(msg):
            enqueue_integration_retry(
                vendor,
                {'kind': kind, 'filename': filename},
                msg,
                get_setting=get_setting,
            )
    except Exception:
        import logging
        logging.getLogger(__name__).exception('enqueue_yara_vendor_failure vendor=%s', vendor)
