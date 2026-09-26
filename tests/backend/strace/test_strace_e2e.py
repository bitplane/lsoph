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


def test_killed_process_releases_its_files(tmp_path):
    """A process killed while holding a file open must not leave it open."""
    target = tmp_path / "held"
    target.write_text("x")
    files = _trace(
        [
            "python3",
            "-c",
            f"import os; f = open({str(target)!r}); os.kill(os.getpid(), 9)",
        ]
    )

    if not files:
        pytest.skip("strace produced no events (ptrace likely blocked here)")

    info = files[bytes(target)]
    assert not info.is_open


def test_stop_terminates_the_traced_tree_promptly():
    """stop() must not wait for a long-running traced child to finish.

    The tracer runs in its own process group; stop() signals the whole group so
    strace and its `sleep 60` child die together. Before this fix stop() blocked
    until the child exited (the child inherited strace's stderr pipe, so wait()
    never returned), so quitting the UI hung.
    """

    async def scenario():
        monitor = Monitor(identifier="stop")
        backend = Strace(monitor)
        run = asyncio.create_task(backend.run_command(["sleep", "60"]))
        await asyncio.sleep(1.5)  # let strace attach and start the child

        process = backend._process  # captured before stop() clears it
        if process is None:
            return None  # strace never launched (ptrace blocked); caller skips
        # If stop() hung waiting for `sleep 60`, these wait_for calls would fire.
        await asyncio.wait_for(backend.stop(), timeout=5.0)
        await asyncio.wait_for(run, timeout=5.0)
        return process

    logging.disable(logging.CRITICAL)
    try:
        process = asyncio.run(asyncio.wait_for(scenario(), timeout=20))
    finally:
        logging.disable(logging.NOTSET)

    if process is None:
        pytest.skip("strace did not launch (ptrace likely blocked here)")
    assert process.returncode is not None  # tracer group actually reaped
