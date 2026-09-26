"""Tests for the FreeBSD truss output parser, from the documented truss(1) format."""

from lsoph.backend.truss.parse import parse_truss_line


def _parse(line):
    return parse_truss_line(line, timestamp=1.0)


def test_successful_openat_is_parsed():
    """A successful openat yields args and the decimal return value."""
    event = _parse('34233: openat(AT_FDCWD,"/dev/urandom",O_RDONLY,00) = 24 (0x18)')

    assert event.pid == 34233
    assert event.syscall == "openat"
    assert event.args == ["AT_FDCWD", b"/dev/urandom", "O_RDONLY", 0]
    assert event.result_int == 24
    assert event.success


def test_error_return_maps_errno_to_name():
    """An ERR#2 failure becomes ENOENT with result -1 and success False."""
    event = _parse(
        "100: open(\"/etc/nope\",O_RDONLY,00) ERR#2 'No such file or directory'"
    )

    assert event.syscall == "open"
    assert event.args == [b"/etc/nope", "O_RDONLY", 0]
    assert event.result_int == -1
    assert event.error_name == "ENOENT"
    assert not event.success


def test_pid_prefix_with_leading_spaces():
    """The %5d: prefix pads small PIDs with spaces, which are stripped."""
    event = _parse("  42: close(3) = 0 (0x0)")

    assert event.pid == 42
    assert event.syscall == "close"
    assert event.args == [3]


def test_freebsd_name_is_aliased_to_handler_name():
    """fstatat is remapped to the newfstatat handler name."""
    event = _parse('42: fstatat(AT_FDCWD,"/lib/x",0x7fffffffe0d0,0x0) = 0 (0x0)')

    assert event.syscall == "newfstatat"


def test_fork_return_is_the_child_pid():
    """A successful fork records the returned value as the child PID."""
    event = _parse("34233: fork() = 4321 (0x10e9)")

    assert event.syscall == "fork"
    assert event.child_pid == 4321


def test_signal_line_is_not_a_syscall():
    """A SIGNAL line is not a syscall event."""
    assert _parse("34233: SIGNAL 17 (SIGCHLD)") is None


def test_process_exit_becomes_exit_event():
    """A `process exit` line becomes an exit syscall so the monitor cleans up."""
    event = _parse("34233: process exit, rval = 0")

    assert event.pid == 34233
    assert event.syscall == "exit"


def test_unparseable_line_returns_none():
    """A line that is not truss output is skipped."""
    assert _parse("this is not truss output") is None


def test_fork_in_the_child_has_no_child_pid():
    """The parent's fork returns the child pid; the child's own returns 0."""
    assert _parse("100: fork() = 101 (0x65)").child_pid == 101
    assert _parse("101: fork() = 0 (0x0)").child_pid is None
