"""End-to-end-minus-subprocess test for the ktrace/kdump backend: feed kdump
records through Ktrace.process_lines and check the resulting Monitor state.
Exercises the stateful parser + the shared syscall dispatch without needing BSD.
"""

import asyncio

from lsoph.backend.ktrace.backend import Ktrace
from lsoph.monitor import Monitor


def _run(lines):
    async def gen():
        for line in lines:
            yield line.encode()

    async def collect():
        monitor = Monitor(identifier="ktrace")
        backend = Ktrace(monitor)
        await backend.process_lines(gen(), attach_ids=None)
        return monitor

    return asyncio.run(collect())


def test_open_read_close_is_tracked():
    """An open/read/close run leaves the file closed with bytes counted."""
    monitor = _run(
        [
            "  100 cat  CALL  open(0x7fff,0x0,0x0)",
            '  100 cat  NAMI  "/etc/hosts"',
            "  100 cat  RET   open 3",
            "  100 cat  CALL  read(0x3,0x8000,0x80)",
            "  100 cat  RET   read 128",
            "  100 cat  CALL  close(0x3)",
            "  100 cat  RET   close 0",
        ]
    )

    info = monitor.files[b"/etc/hosts"]
    assert info.status == "closed"
    assert info.bytes_read == 128


def test_failed_open_is_enoent_error():
    """A failed open (RET errno 2) records the path as an ENOENT error."""
    monitor = _run(
        [
            "  100 cat  CALL  open(0xdead,0x0,0x0)",
            '  100 cat  NAMI  "/nope"',
            "  100 cat  RET   open -1 errno 2",
        ]
    )

    info = monitor.files[b"/nope"]
    assert info.status == "error"
    assert info.last_error_enoent is True
