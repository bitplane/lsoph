"""Tests for strace unfinished/resumed syscall reconstruction (the -f split lines).

A blocking syscall under `strace -f` is emitted as two interleaved lines:
    1234 read(3,  <unfinished ...>
    1234 <... read resumed> "data", 100) = 4
These are spliced back into one complete Syscall.
"""

import asyncio

from lsoph.backend.strace.parse import parse_strace_stream_pyparsing
from lsoph.backend.strace.parser_defs import split_resumed, split_unfinished


def _run(lines):
    async def gen():
        for line in lines:
            yield line.encode()

    async def collect():
        out = []
        async for syscall in parse_strace_stream_pyparsing(
            gen(), None, asyncio.Event()
        ):
            out.append(syscall)
        return out

    return asyncio.run(collect())


def test_split_unfinished_extracts_pid_and_prefix():
    """An unfinished line yields its PID and the body before the marker."""
    result = split_unfinished("1234 read(3,  <unfinished ...>")

    assert result == (1234, "read(3,")


def test_split_resumed_extracts_pid_name_and_remainder():
    """A resumed line yields its PID, syscall name, and the text after the marker."""
    result = split_resumed('1234 <... read resumed> "data", 100) = 4')

    assert result == (1234, "read", ' "data", 100) = 4')


def test_normal_line_is_not_treated_as_split():
    """A complete syscall line is neither unfinished nor resumed."""
    line = '1234 openat(AT_FDCWD, "/x", O_RDONLY) = 3'

    assert split_unfinished(line) is None
    assert split_resumed(line) is None


def test_unfinished_then_resumed_is_reconstructed():
    """The two halves of a blocked read splice into one complete Syscall."""
    events = _run(
        [
            "1234 read(3,  <unfinished ...>",
            '1234 <... read resumed> "data", 100) = 4',
        ]
    )

    assert len(events) == 1
    event = events[0]
    assert event.pid == 1234
    assert event.syscall == "read"
    assert event.args == [3, b"data", 100]
    assert event.result_int == 4


def test_reconstruction_survives_interleaved_other_pid():
    """A different PID's complete line between the two halves does not break splicing."""
    events = _run(
        [
            "1234 read(3,  <unfinished ...>",
            '5678 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 5',
            '1234 <... read resumed> "data", 100) = 4',
        ]
    )

    by_pid = {e.pid: e for e in events}
    assert set(by_pid) == {1234, 5678}
    assert by_pid[1234].syscall == "read"
    assert by_pid[1234].args == [3, b"data", 100]


def test_resumed_with_no_remaining_args():
    """A syscall whose args were fully printed before blocking still reconstructs."""
    events = _run(
        [
            "1234 fsync(3 <unfinished ...>",
            "1234 <... fsync resumed> ) = 0",
        ]
    )

    assert len(events) == 1
    assert events[0].syscall == "fsync"
    assert events[0].args == [3]
    assert events[0].result_int == 0


def test_resumed_eintr_with_trailing_comma_reconstructs():
    """An interrupted (EINTR) resume can leave a trailing comma; it still parses."""
    events = _run(
        [
            "1234 read(3,  <unfinished ...>",
            "1234 <... read resumed>) = -1 EINTR (Interrupted system call)",
        ]
    )

    assert len(events) == 1
    assert events[0].syscall == "read"
    assert events[0].result_int == -1
    assert events[0].error_name == "EINTR"


def test_orphan_resumed_line_is_skipped():
    """A resumed line with no matching unfinished call is dropped, not crashed."""
    events = _run(['9999 <... read resumed> "x", 1) = 1'])

    assert events == []


def test_exit_markers_become_exit_events():
    """A killed task never calls exit_group; its +++ marker stands in."""
    events = _run(
        [
            '42 openat(AT_FDCWD, "/tmp/a", O_RDONLY) = 3',
            "42 +++ killed by SIGKILL +++",
            "43 +++ exited with 1 +++",
            "44 +++ killed by SIGSEGV (core dumped) +++",
        ]
    )

    assert [(e.pid, e.syscall) for e in events[1:]] == [
        (42, "exit_group"),
        (43, "exit_group"),
        (44, "exit_group"),
    ]


def test_clone3_reports_its_child_pid():
    """glibc's pthread_create and posix_spawn use clone3."""
    (event,) = _run(
        ["42 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88) = 43"]
    )

    assert event.syscall == "clone3"
    assert event.child_pid == 43
