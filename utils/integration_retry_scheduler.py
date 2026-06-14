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

                    summaries = process_all_integration_retry_queues(_app._get_setting, force=False)
                    for vendor, summary in summaries.items():
                        logger.info(
                            'Integration retry %s: processed=%s ok=%s fail=%s remaining=%s',
                            vendor,
                            summary.get('processed'),
                            summary.get('succeeded'),
                            summary.get('failed'),
                            summary.get('remaining'),
                        )
            except Exception:
                logger.exception('Integration retry scheduler tick failed')
            time.sleep(SCHEDULER_WAKE_SEC)

    t = threading.Thread(target=_loop, name='integration-retry-scheduler', daemon=True)
    t.start()
    logger.info('Integration retry scheduler started (wake every %ss)', SCHEDULER_WAKE_SEC)


def start_cortex_xdr_retry_scheduler(app) -> None:
    """Backward-compatible alias."""
    start_integration_retry_scheduler(app)
