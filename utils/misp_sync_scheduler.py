"""
In-app MISP pull scheduler (daemon thread).

Production may also use ``ziochub-misp-sync.timer`` (systemd); both call the same
``run_misp_sync_if_due_with_lock`` logic. The timer/job and this scheduler wake
every ~5 minutes; the admin ``misp_pull_interval`` setting controls how often an
actual MISP pull runs.
"""
from __future__ import annotations

import logging
import threading
import time

from utils.misp_sync_runner import SCHEDULER_WAKE_SEC

logger = logging.getLogger(__name__)

_started = False
_start_lock = threading.Lock()


def start_misp_sync_scheduler(app) -> None:
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
        from utils.misp_sync_runner import run_misp_sync_if_due_with_lock

        # Short initial delay so the web app finishes booting.
        time.sleep(30)
        while True:
            try:
                with app_obj.app_context():
                    run_misp_sync_if_due_with_lock(app_obj)
            except Exception:
                logger.exception('MISP sync scheduler tick failed')
            time.sleep(SCHEDULER_WAKE_SEC)

    t = threading.Thread(target=_loop, name='misp-sync-scheduler', daemon=True)
    t.start()
    logger.info('MISP sync scheduler started (wake every %ss)', SCHEDULER_WAKE_SEC)
