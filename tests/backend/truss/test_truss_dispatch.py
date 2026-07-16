"""End-to-end-minus-subprocess test for the truss backend: feed documented truss
lines through Truss.process_lines and check the resulting Monitor state.

This exercises parse + dispatch + close detection without needing FreeBSD/truss.
"""

import asyncio

from lsoph.backend.truss.backend import Truss
from lsoph.monitor import Monitor


def _run(lines):
    async def gen():
        for line in lines:
            yield line.encode()

    async def collect():
        monitor = Monitor(identifier="truss")
        backend = Truss(monitor)
        await backend.process_lines(gen(), attach_ids=None)
        return monitor

    return asyncio.run(collect())


def test_open_read_close_sequence_is_tracked():
    """An open/read/close run leaves the file closed with the read bytes counted."""
    monitor = _run(
        [
            '100: openat(AT_FDCWD,"/etc/hosts",O_RDONLY,00) = 3 (0x3)',
            '100: read(3,"data",128) = 128 (0x80)',
            "100: close(3) = 0 (0x0)",
        ]
    )

    info = monitor.files[b"/etc/hosts"]
    assert info.status == "closed"
    assert info.bytes_read == 128


def test_failed_open_is_recorded_as_enoent_error():
    """A failed open (ERR#2 -> ENOENT) records error status and the ENOENT flag."""
    monitor = _run(
        ["100: open(\"/nope\",O_RDONLY,00) ERR#2 'No such file or directory'"]
    )

    info = monitor.files[b"/nope"]
    assert info.status == "error"
    assert info.last_error_enoent is True


def test_process_exit_closes_open_fds():
    """A `process exit` line closes the process's still-open files."""
    monitor = _run(
        [
            '100: openat(AT_FDCWD,"/etc/hosts",O_RDONLY,00) = 3 (0x3)',
            "100: process exit, rval = 0",
        ]
    )

    assert monitor.files[b"/etc/hosts"].status == "closed"
