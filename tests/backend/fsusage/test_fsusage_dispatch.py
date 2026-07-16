"""End-to-end-minus-subprocess test for the fs_usage backend: feed documented
fs_usage lines through Fsusage.process_lines and check the resulting Monitor
state. Exercises parse + dispatch + fd/close correlation without needing macOS.
"""

import asyncio

from lsoph.backend.fsusage.backend import Fsusage
from lsoph.monitor import Monitor


def _run(lines):
    async def gen():
        for line in lines:
            yield line.encode()

    async def collect():
        monitor = Monitor(identifier="fsusage")
        backend = Fsusage(monitor)
        await backend.process_lines(gen(), attach_ids=None)
        return monitor

    return asyncio.run(collect())


def test_open_read_close_correlates_by_fd():
    """read/close carry no path; they correlate to the open via the fd (thread key)."""
    monitor = _run(
        [
            "00:00:00.000001  open     F=3   (R_____)  /etc/hosts   0.000010   cat.500",
            "00:00:00.000002  read     F=3   B=0x80              0.000005   cat.500",
            "00:00:00.000003  close    F=3                       0.000002   cat.500",
        ]
    )

    info = monitor.files[b"/etc/hosts"]
    assert info.status == "closed"
    assert info.bytes_read == 0x80


def test_stat_records_accessed_file():
    """An lstat64 records the path as accessed."""
    monitor = _run(
        ["00:00:00.000001  lstat64   /Users/me/file.txt   0.000006   node.42"]
    )

    assert monitor.files[b"/Users/me/file.txt"].status == "accessed"


def test_failed_open_is_enoent_error():
    """A failed open ([ 2]) records the path as an ENOENT error."""
    monitor = _run(["00:00:00.000001  open   [  2]   /nope   0.000010   cat.500"])

    info = monitor.files[b"/nope"]
    assert info.status == "error"
    assert info.last_error_enoent is True


def test_read_on_unmapped_fd_is_ignored():
    """A read on an fd we never saw opened is skipped, not a crash."""
    monitor = _run(["00:00:00.000001  read   F=99   B=0x10   0.000005   ghost.1"])

    assert len(monitor) == 0
