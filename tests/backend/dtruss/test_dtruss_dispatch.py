"""End-to-end-minus-subprocess test for the dtruss backend: feed documented
dtruss lines through Dtruss.process_lines and check the resulting Monitor state.
Exercises parse + the shared syscall dispatch without needing macOS/DTrace.
"""

import asyncio

from lsoph.backend.dtruss.backend import Dtruss
from lsoph.monitor import Monitor


def _run(lines):
    async def gen():
        for line in lines:
            yield line.encode()

    async def collect():
        monitor = Monitor(identifier="dtruss")
        backend = Dtruss(monitor)
        await backend.process_lines(gen(), attach_ids=None)
        return monitor

    return asyncio.run(collect())


def test_open_read_close_is_tracked():
    """An open/read/close run leaves the file closed with the read bytes counted."""
    monitor = _run(
        [
            r' 100/0x1:  open("/etc/hosts\0", 0x0, 0x0)		 = 3 0',
            r' 100/0x1:  read(0x3, "data", 0x80)		 = 128 0',
            r" 100/0x1:  close(0x3)		 = 0 0",
        ]
    )

    info = monitor.files[b"/etc/hosts"]
    assert info.status == "closed"
    assert info.bytes_read == 128


def test_failed_open_is_enoent_error():
    """A failed open ( = -1 Err#2) records the path as an ENOENT error."""
    monitor = _run([r' 100/0x1:  open("/nope\0", 0x0, 0x0)		 = -1 Err#2'])

    info = monitor.files[b"/nope"]
    assert info.status == "error"
    assert info.last_error_enoent is True


def test_stat_records_accessed_file():
    """stat64 records the path as accessed."""
    monitor = _run([r' 100/0x1:  stat64("/tmp/x\0", 0x0, 0x0)		 = 0 0'])

    assert monitor.files[b"/tmp/x"].status == "accessed"
