"""
Cortex XDR failed outbound IOC queue — thin wrapper over generic integration retry.
"""

from __future__ import annotations

from typing import Any, Callable

from utils.integration_retry import (
    enqueue_integration_retries,
    enqueue_integration_retry,
    get_integration_retry_queue,
    integration_retry_enabled,
    integration_retry_interval_minutes,
    process_integration_retry_queue,
)

VENDOR = 'cortex_xdr'
KEY_CORTEX_XDR_RETRY_QUEUE = 'cortex_xdr_retry_queue_json'


def get_cortex_xdr_retry_queue(get_setting: Callable[[str, str], str]):
    return get_integration_retry_queue(VENDOR, get_setting)


def cortex_xdr_retry_interval_minutes(get_setting: Callable[[str, str], str]) -> int:
    return integration_retry_interval_minutes(VENDOR, get_setting)


def cortex_xdr_retry_enabled(get_setting: Callable[[str, str], str]) -> bool:
    return integration_retry_enabled(VENDOR, get_setting)


def enqueue_cortex_xdr_retries(
    failures: list[tuple[dict[str, Any], str]],
    *,
    get_setting: Callable[[str, str], str],
) -> None:
    from utils.cortex_xdr import cortex_xdr_is_retriable_failure

    filtered = [(ioc, msg) for ioc, msg in (failures or []) if cortex_xdr_is_retriable_failure(msg)]
    enqueue_integration_retries(VENDOR, filtered, get_setting=get_setting)


def enqueue_cortex_xdr_retry(
    ioc: dict[str, Any],
    error_message: str,
    *,
    get_setting: Callable[[str, str], str],
) -> None:
    from utils.cortex_xdr import cortex_xdr_is_retriable_failure

    if cortex_xdr_is_retriable_failure(error_message):
        enqueue_integration_retry(VENDOR, ioc, error_message, get_setting=get_setting)


def process_cortex_xdr_retry_queue(
    get_setting: Callable[[str, str], str],
    *,
    force: bool = False,
) -> dict[str, Any]:
    return process_integration_retry_queue(VENDOR, get_setting, force=force)
