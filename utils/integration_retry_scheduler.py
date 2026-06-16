"""
In-app integration retry scheduler (daemon thread).

Wakes every 60s and processes due retry queues for all enabled push vendors.
"""

from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)

SCHEDULER_WAKE_SEC = 60

_started = False
_start_lock = threading.Lock()


def start_integration_retry_scheduler(app) -> None:
    global _started
    with _start_lock:
        if _started:
            return
        _started = True

    try:
        app_obj = app._get_current_object()
    except Exception:
        app_obj = app

    def _loop() -> None:
        import app as _app

        time.sleep(45)
        while True:
            try:
                with app_obj.app_context():
                    from utils.integration_retry import process_all_integration_retry_queues
                    from utils.audit_events import audit_integration_retry_tick

                    summaries = process_all_integration_retry_queues(_app._get_setting, force=False)
                    audit_integration_retry_tick(summaries)
                    for vendor, summary in summaries.items():
                        logger.info(
                            'Integration retry %s: processed=%s ok=%s fail=%s remaining=%s',
                            vendor,
                            summary.get('processed'),
                            summary.get('succeeded'),
                            summary.get('failed'),
                            summary.get('remaining'),
                        )
            except Exception as tick_err:
                logger.exception('Integration retry scheduler tick failed')
                try:
                    with app_obj.app_context():
                        from utils.audit_events import audit_log_event

                        audit_log_event(
                            'integration_retry_auto',
                            'fail',
                            scope='scheduler_tick',
                            reason=str(tick_err)[:200],
                        )
                except Exception:
                    pass
            time.sleep(SCHEDULER_WAKE_SEC)

    t = threading.Thread(target=_loop, name='integration-retry-scheduler', daemon=True)
    t.start()
    logger.info('Integration retry scheduler started (wake every %ss)', SCHEDULER_WAKE_SEC)


def start_cortex_xdr_retry_scheduler(app) -> None:
    """Backward-compatible alias."""
    start_integration_retry_scheduler(app)
