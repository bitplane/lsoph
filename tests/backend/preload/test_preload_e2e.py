"""End-to-end test for the preload backend: compile the shim, run a real command
under it, and confirm the Monitor captured the file it opened.

Skipped where the backend can't run (no C compiler, or macOS/Windows).
"""

import asyncio
import logging

import pytest

from lsoph.backend.preload.backend import Preload
from lsoph.monitor import Monitor

pytestmark = pytest.mark.skipif(
    not Preload.is_available(),
    reason="preload backend unavailable (no compiler / wrong OS)",
)


def test_run_command_captures_opened_file():
    """Running `cat /etc/hostname` under the shim records the file as opened."""
    logging.disable(logging.CRITICAL)
    try:
        monitor = Monitor(identifier="e2e")
        backend = Preload(monitor)
        asyncio.run(
            asyncio.wait_for(
                backend.run_command(["sh", "-c", "cat /etc/hostname; sleep 0.3"]),
                timeout=20,
            )
        )
    finally:
        logging.disable(logging.NOTSET)

    files = {fi.path for fi in monitor}
    assert b"/etc/hostname" in files
    info = monitor.files[b"/etc/hostname"]
    assert "OPEN" in list(info.recent_event_types)
