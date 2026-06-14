"""
In-app Cortex XDR retry scheduler (daemon thread).

Wakes every 60s and processes the failed IOC queue when the configured interval elapses.
"""
from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)

SCHEDULER_WAKE_SEC = 60

_started = False
_start_lock = threading.Lock()


def start_cortex_xdr_retry_scheduler(app) -> None:
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
                    from utils.cortex_xdr_retry import (
                        cortex_xdr_retry_enabled,
                        process_cortex_xdr_retry_queue,
                    )

                    if cortex_xdr_retry_enabled(_app._get_setting):
                        summary = process_cortex_xdr_retry_queue(_app._get_setting, force=False)
                        if summary.get('processed'):
                            logger.info(
                                'Cortex XDR retry tick: processed=%s ok=%s fail=%s remaining=%s',
                                summary.get('processed'),
                                summary.get('succeeded'),
                                summary.get('failed'),
                                summary.get('remaining'),
                            )
            except Exception:
                logger.exception('Cortex XDR retry scheduler tick failed')
            time.sleep(SCHEDULER_WAKE_SEC)

    t = threading.Thread(target=_loop, name='cortex-xdr-retry-scheduler', daemon=True)
    t.start()
    logger.info('Cortex XDR retry scheduler started (wake every %ss)', SCHEDULER_WAKE_SEC)
