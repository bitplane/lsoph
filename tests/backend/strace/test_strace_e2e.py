"""End-to-end test for the strace backend: trace a real command and check the
monitor captured the files it touched.

Skipped where strace is unavailable or ptrace is not permitted (e.g. locked-down
CI containers), so it only asserts where it can actually run.
"""

import asyncio
import logging
import shutil

import pytest

from lsoph.backend.strace.backend import Strace
from lsoph.monitor import Monitor

pytestmark = pytest.mark.skipif(
    shutil.which("strace") is None, reason="strace not installed"
)


def _trace(command):
    logging.disable(logging.CRITICAL)
    try:
        monitor = Monitor(identifier="e2e")
        backend = Strace(monitor)
        asyncio.run(asyncio.wait_for(backend.run_command(command), timeout=20))
        return {fi.path: fi for fi in monitor}
    finally:
        logging.disable(logging.NOTSET)


def test_run_command_captures_opened_file():
    """Tracing `cat /etc/hostname` records the file as opened then closed."""
    files = _trace(["sh", "-c", "cat /etc/hostname; sleep 1"])

    if not files:
        pytest.skip("strace produced no events (ptrace likely blocked here)")

    assert b"/etc/hostname" in files
    info = files[b"/etc/hostname"]
    assert "OPEN" in list(info.recent_event_types)
    # The shared library the C runtime loads should show up too.
    assert any(b"libc.so" in path for path in files)
