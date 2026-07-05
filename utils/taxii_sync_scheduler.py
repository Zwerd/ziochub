"""
In-app TAXII pull scheduler (daemon thread).

Skipped when ``ZIOCHUB_USE_SYSTEMD_SYNC=1`` (use ``ziochub-taxii-sync.timer`` instead).
"""
from __future__ import annotations

import logging
import threading
import time

from utils.misp_sync_runner import SCHEDULER_WAKE_SEC

logger = logging.getLogger(__name__)

_started = False
_start_lock = threading.Lock()


def start_taxii_sync_scheduler(app) -> None:
    from utils.inapp_sync_policy import inapp_taxii_sync_enabled

    if not inapp_taxii_sync_enabled():
        logger.info(
            'In-app TAXII sync scheduler disabled '
            '(production: ziochub-taxii-sync.timer; dev: set ZIOCHUB_INAPP_TAXII_SYNC=1)'
        )
        return

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
        from utils.taxii_sync_runner import run_taxii_sync_if_due_with_lock

        time.sleep(30)
        while True:
            try:
                with app_obj.app_context():
                    run_taxii_sync_if_due_with_lock(app_obj)
            except Exception:
                logger.exception('TAXII sync scheduler tick failed')
            time.sleep(SCHEDULER_WAKE_SEC)

    t = threading.Thread(target=_loop, name='taxii-sync-scheduler', daemon=True)
    t.start()
    logger.info('TAXII sync scheduler started (wake every %ss)', SCHEDULER_WAKE_SEC)
