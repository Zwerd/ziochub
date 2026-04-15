"""
IOC push retry service.

Keeps the admin route thin by encapsulating:
- loading last recorded push context/results
- selecting only failed targets (by URL)
- pushing again only to those targets
- persisting updated telemetry
"""

from __future__ import annotations

import json
from typing import Callable, Tuple


class RetryError(Exception):
    """Base error for retry flow."""


class NoRecordedContextError(RetryError):
    """No stored context/results exist yet."""


class InvalidStoredContextError(RetryError):
    """Stored context exists but is invalid/unusable."""


class NoMatchingTargetsError(RetryError):
    """Targets list does not contain stored failed URLs."""


def retry_last_failed_ioc_push(
    *,
    kind: str,
    get_setting: Callable[[str, str], str],
    audit_log_fn=None,
) -> Tuple[dict, str]:
    """
    Retry failed IOC push targets for the last recorded event of `kind`.

    Returns: (data, message)
    - data: { retried: int, ...push_results }
    - message: human-friendly status message

    Raises:
    - NoRecordedContextError
    - InvalidStoredContextError
    - NoMatchingTargetsError
    """
    kind_l = (kind or "").strip().lower()
    if kind_l not in ("create", "expire", "manual_remove"):
        raise ValueError("Invalid kind")

    from utils.integration_telemetry import (
        KEY_IOC_EXPIRE_PUSH_CONTEXT,
        KEY_IOC_EXPIRE_PUSH_RESULTS,
        KEY_IOC_MANUAL_REMOVE_PUSH_CONTEXT,
        KEY_IOC_MANUAL_REMOVE_PUSH_RESULTS,
        KEY_IOC_PUSH_CONTEXT,
        KEY_IOC_PUSH_RESULTS,
        record_ioc_push_results,
    )

    if kind_l == "expire":
        k_res, k_ctx = KEY_IOC_EXPIRE_PUSH_RESULTS, KEY_IOC_EXPIRE_PUSH_CONTEXT
    elif kind_l == "manual_remove":
        k_res, k_ctx = KEY_IOC_MANUAL_REMOVE_PUSH_RESULTS, KEY_IOC_MANUAL_REMOVE_PUSH_CONTEXT
    else:
        k_res, k_ctx = KEY_IOC_PUSH_RESULTS, KEY_IOC_PUSH_CONTEXT

    raw_res = (get_setting(k_res, "") or "").strip()
    raw_ctx = (get_setting(k_ctx, "") or "").strip()
    if not raw_res or not raw_ctx:
        raise NoRecordedContextError("No recorded push context/results to retry yet.")

    try:
        last = json.loads(raw_res)
    except Exception:
        last = {}
    try:
        ctx = json.loads(raw_ctx)
    except Exception:
        ctx = {}
    if not isinstance(ctx, dict) or not ctx:
        raise InvalidStoredContextError("Invalid stored context")

    failed_urls = set()
    for r in (last.get("results") or []):
        try:
            if not r.get("success"):
                u = (r.get("url") or "").strip()
                if u:
                    failed_urls.add(u)
        except Exception:
            continue

    if not failed_urls:
        return {"retried": 0, "results": last.get("results") or []}, "No failed targets to retry."

    from utils.ioc_push import load_targets, push_one_ioc_to_targets

    targets = [
        t
        for t in load_targets()
        if isinstance(t, dict) and (t.get("url") or "").strip() in failed_urls
    ]
    if not targets:
        raise NoMatchingTargetsError("No matching targets found (URLs changed?)")

    res = push_one_ioc_to_targets(ctx, targets, audit_log_fn=audit_log_fn)
    # Update telemetry for this kind with the same stored context
    record_ioc_push_results(res, kind=kind_l, context=ctx)

    return {"retried": len(targets), **res}, "Retry completed"

