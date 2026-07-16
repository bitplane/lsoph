"""Dispatch tests for the preload backend: feed the shim's tab-separated records
through Preload.process_lines and check Monitor state. No subprocess needed."""

import asyncio

from lsoph.backend.preload.backend import Preload
from lsoph.monitor import Monitor


def _run(records):
    async def gen():
        for rec in records:
            yield rec

    async def collect():
        monitor = Monitor(identifier="preload")
        backend = Preload(monitor)
        await backend.process_lines(gen(), attach_ids=None)
        return monitor

    return asyncio.run(collect())


def test_open_read_close_records_are_applied():
    """OPEN/READ/CLOSE records assemble into a tracked, then closed, file."""
    monitor = _run(
        [
            b"OPEN\t100\t3\t3\t0\t/etc/hosts",
            b"READ\t100\t3\t128\t0\t",
            b"CLOSE\t100\t3\t0\t0\t",
        ]
    )

    info = monitor.files[b"/etc/hosts"]
    assert info.status == "closed"
    assert info.bytes_read == 128


def test_failed_open_is_enoent_error():
    """An OPEN with errno 2 records the path as an ENOENT error."""
    monitor = _run([b"OPEN\t100\t-1\t-1\t2\t/nope"])

    info = monitor.files[b"/nope"]
    assert info.status == "error"
    assert info.last_error_enoent is True


def test_rename_uses_two_paths():
    """A RENAME record carries old and new paths."""
    monitor = _run(
        [
            b"OPEN\t100\t3\t3\t0\t/a",
            b"CLOSE\t100\t3\t0\t0\t",
            b"RENAME\t100\t-1\t0\t0\t/a\t/b",
        ]
    )

    assert b"/b" in monitor.files


def test_malformed_record_is_skipped():
    """A record without enough fields is ignored, not a crash."""
    monitor = _run([b"OPEN\t100", b"garbage"])

    assert len(monitor) == 0
