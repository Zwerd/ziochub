"""
Outbound IOC integration hook (single entrypoint).

Goal: ensure all current and future API endpoints that mutate IOC lifecycle
trigger the same outbound behavior (push + telemetry) by calling ONE helper.

Vendor-specific integrations (Cortex XDR, Google SecOps) that are not the generic
IOC HTTP push use ``schedule_auxiliary_vendor_integrations`` with the same IOC context dict.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)


def schedule_auxiliary_vendor_integrations(
    app,
    contexts: list[dict[str, Any]],
    *,
    delay_sec: float = 0.05,
) -> None:
    """
    Fire-and-forget Cortex XDR + Google SecOps hooks (when enabled in Integrations).

    ``contexts`` items match ``ioc_context_from_submission`` (``type``, ``value``, ``action``, …).
    Skips rows whose analyst is the MISP sync user (same loop-avoidance as IOC HTTP push).
    Independent of ``ioc_push_enabled`` / configured HTTP targets.
    """
    if not contexts:
        return
    try:
        import app as _app
        misp_sync = (_app._get_setting('misp_sync_user', 'misp_sync') or 'misp_sync').strip().lower()
    except Exception:
        misp_sync = 'misp_sync'

    filtered: list[dict[str, Any]] = []
    for c in contexts:
        if not isinstance(c, dict):
            continue
        if (str(c.get('analyst') or '')).strip().lower() == misp_sync:
            continue
        filtered.append(c)

    if not filtered:
        return

    try:
        app_obj = app._get_current_object()
    except Exception:
        app_obj = app

    def _worker() -> None:
        with app_obj.app_context():
            for ctx in filtered:
                try:
                    from utils.cortex_xdr import cortex_xdr_push_ioc_from_context

                    cortex_xdr_push_ioc_from_context(ctx)
                except Exception:
                    logger.exception('Cortex XDR auxiliary IOC push failed')
                try:
                    from utils.google_secops import google_secops_push_ioc_from_context

                    google_secops_push_ioc_from_context(ctx)
                except Exception:
                    logger.exception('Google SecOps auxiliary IOC push failed')
                if delay_sec > 0:
                    time.sleep(delay_sec)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def schedule_outbound_ioc_event(
    app,
    *,
    action: str,
    remove_reason: str = '',
    ioc_type: str,
    value: str,
    analyst: str,
    ticket_id: Optional[str] = None,
    comment: Optional[str] = None,
    expiration_date: Optional[datetime] = None,
    campaign_id: Optional[int] = None,
    tags_json: Optional[str] = None,
    submission_method: str = 'api',
    user_id: Optional[int] = None,
    created_at: Optional[datetime] = None,
) -> None:
    """
    Fire-and-forget outbound push for one IOC lifecycle event.

    - Uses ioc_push background thread (no request latency).
    - Telemetry is recorded by the ioc_push worker via integration_telemetry.
    - Cortex XDR / Google SecOps: ``schedule_auxiliary_vendor_integrations`` when those flags are on.
    """
    try:
        from utils.ioc_push import ioc_context_from_submission, schedule_ioc_push_batch

        ctx: dict[str, Any] = ioc_context_from_submission(
            ioc_type=ioc_type,
            value=value,
            analyst=analyst,
            ticket_id=ticket_id,
            comment=comment,
            expiration_date=expiration_date,
            campaign_id=campaign_id,
            tags_json=tags_json,
            submission_method=submission_method,
            user_id=user_id,
            created_at=created_at,
            action=action,
            remove_reason=remove_reason,
        )
        schedule_ioc_push_batch(app, [ctx])
        schedule_auxiliary_vendor_integrations(app, [ctx])
    except Exception as e:
        # Must never crash caller; outbound integrations are best-effort.
        logger.warning('schedule_outbound_ioc_event failed: %s', e)
