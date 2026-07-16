"""Tests for the stateful BSD kdump parser (CALL / NAMI / RET records)."""

from lsoph.backend.ktrace.parse import KdumpParser


def _feed(lines):
    """Feed lines to a fresh parser; return the list of emitted Syscalls."""
    parser = KdumpParser()
    events = []
    for line in lines:
        event = parser.feed(line, timestamp=1.0)
        if event is not None:
            events.append(event)
    return events


def test_open_call_nami_ret_is_assembled():
    """CALL + NAMI + RET assemble into one open with path, flags and fd."""
    events = _feed(
        [
            "  517 ls  CALL  open(0x7fff,0x0,0x1b6)",
            '  517 ls  NAMI  "/etc/hosts"',
            "  517 ls  RET   open 3",
        ]
    )

    assert len(events) == 1
    event = events[0]
    assert event.syscall == "open"
    assert event.pid == 517
    assert event.args == [b"/etc/hosts", 0, 0x1B6]
    assert event.result_int == 3


def test_read_without_nami_uses_call_args():
    """A read has no NAMI; fd/count come from CALL, bytes from RET."""
    events = _feed(
        ["  517 ls  CALL  read(0x3,0x8049000,0x1000)", "  517 ls  RET   read 4096"]
    )

    assert events[0].syscall == "read"
    assert events[0].args[0] == 3
    assert events[0].result_int == 4096


def test_error_ret_maps_errno():
    """A RET with `errno 2` becomes an ENOENT failure."""
    events = _feed(
        [
            "  517 ls  CALL  open(0xdead,0x0,0x0)",
            '  517 ls  NAMI  "/nope"',
            "  517 ls  RET   open -1 errno 2 No such file or directory",
        ]
    )

    assert events[0].result_int == -1
    assert events[0].error_name == "ENOENT"
    assert not events[0].success


def test_rename_takes_two_nami_paths():
    """rename's two pointer args are replaced by its two NAMI paths."""
    events = _feed(
        [
            "  517 ls  CALL  rename(0x1,0x2)",
            '  517 ls  NAMI  "/a"',
            '  517 ls  NAMI  "/b"',
            "  517 ls  RET   rename 0",
        ]
    )

    assert events[0].syscall == "rename"
    assert events[0].args == [b"/a", b"/b"]


def test_exit_call_is_emitted_without_ret():
    """An exit has no RET; it is emitted on the CALL record."""
    events = _feed(["  517 ls  CALL  exit(0)"])

    assert len(events) == 1
    assert events[0].syscall == "exit"


def test_interleaved_pids_do_not_collide():
    """Two PIDs mid-syscall keep separate pending state."""
    events = _feed(
        [
            "  888 sh  CALL  open(0x1,0x0,0x0)",
            "  517 ls  CALL  stat(0x1,0x2)",
            '  888 sh  NAMI  "/from888"',
            '  517 ls  NAMI  "/from517"',
            "  888 sh  RET   open 7",
            "  517 ls  RET   stat 0",
        ]
    )

    by_pid = {e.pid: e for e in events}
    assert by_pid[888].args[0] == b"/from888"
    assert by_pid[517].args[0] == b"/from517"


def test_non_record_line_is_ignored():
    """A line that isn't a kdump record yields nothing."""
    assert _feed(["not a kdump record"]) == []
