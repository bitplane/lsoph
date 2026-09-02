# Filename: src/lsoph/backend/etw/backend.py
"""
Windows ETW backend: consumes Microsoft-Windows-Kernel-File events.

This is a third engine shape -- neither a subprocess line tracer nor a poller.
ProcessTrace delivers events via a callback on a blocking thread, so the
session runs in its own thread and pumps decoded events into the asyncio loop,
where they are filtered to the watched PIDs and dispatched to the Monitor.

The kernel-file provider is system-wide (no per-PID subscription), so the PID
filter lives here: the initial PIDs plus periodically-discovered descendants.
Requires elevation. Under Wine the ETW APIs are stubs, so is_available() is
True there but the session fails at start; NOT yet validated on real Windows.
"""

import asyncio
import logging
import sys
import threading
import time

from lsoph.util.pid import get_descendants

from ..base import Backend
from .dispatch import process_file_event
from .parse import FileEvent

log = logging.getLogger(__name__)

SESSION_NAME = "lsoph-etw"
# Re-scan for descendant processes this often (seconds).
CHILD_CHECK_INTERVAL = 1.0


class Etw(Backend):
    """Async backend consuming Windows kernel file events via ETW."""

    backend_name = "etw"
    description = "ETW kernel tracer; needs admin; not yet validated on real Windows"

    @staticmethod
    def is_available() -> bool:
        """ETW kernel providers exist on Windows and require elevation."""
        if sys.platform != "win32":
            return False
        from .session import is_admin

        return is_admin()

    async def attach(self, pids: list[int]):
        """Trace file events system-wide, dispatching those from `pids` (and
        their descendants) until stopped."""
        if not pids:
            return
        from . import session as session_module

        watched = {p for p in pids if p > 0}
        watched_lock = threading.Lock()
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[FileEvent] = asyncio.Queue()

        def on_event(event: FileEvent) -> None:
            # Called on the ProcessTrace thread.
            # Filter the system-wide provider here so unrelated file activity
            # cannot build an unbounded backlog on the asyncio loop.
            with watched_lock:
                if event.pid not in watched:
                    return
            loop.call_soon_threadsafe(queue.put_nowait, event)

        session = session_module.KernelFileSession(SESSION_NAME, on_event)

        def pump() -> None:
            # Session failures (no privilege, ETW unavailable) land here on
            # the consumer thread; log them instead of a raw thread traceback.
            # The loop below notices the dead thread and stops the backend.
            try:
                session.run()
            except OSError as e:
                log.error(f"ETW session failed: {e}")

        thread = threading.Thread(target=pump, name="etw_consumer")
        thread.start()

        next_child_check = time.monotonic() + CHILD_CHECK_INTERVAL
        try:
            while not self.should_stop:
                if not thread.is_alive():
                    log.error("ETW consumer thread died; stopping backend.")
                    break
                if time.monotonic() >= next_child_check:
                    with watched_lock:
                        watched_snapshot = list(watched)
                    descendants = set()
                    for pid in watched_snapshot:
                        descendants.update(get_descendants(pid))
                    with watched_lock:
                        watched.update(descendants)
                    next_child_check = time.monotonic() + CHILD_CHECK_INTERVAL
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                process_file_event(event, self.monitor, watched)
        finally:
            session.stop()
            thread.join(timeout=5.0)
            log.info("ETW session stopped.")
