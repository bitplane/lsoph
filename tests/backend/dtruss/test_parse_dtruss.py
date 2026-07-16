"""Tests for the dtruss output parser, from the documented dtruss -f format."""

from lsoph.backend.dtruss.parse import parse_dtruss_line


def _parse(line):
    return parse_dtruss_line(line, timestamp=1.0)


def test_open_extracts_pid_path_and_fd():
    """A successful open yields the real pid, the path, and the returned fd."""
    event = _parse(r' 1871/0x45006d:  open("/etc/hosts\0", 0x0, 0x0)		 = 3 0')

    assert event.pid == 1871
    assert event.syscall == "open"
    assert event.args[0] == b"/etc/hosts"
    assert event.result_int == 3
    assert event.success


def test_close_hex_fd_is_decoded():
    """close(0x3) parses the hex fd to an int."""
    event = _parse(r" 1871/0x45006d:  close(0x3)		 = 0 0")

    assert event.syscall == "close"
    assert event.args == [3]


def test_read_fd_buffer_and_count():
    """read carries fd, buffer and count; the return is the byte count."""
    event = _parse(r' 1871/0x45006d:  read(0x3, "data", 0x1000)		 = 5 0')

    assert event.syscall == "read"
    assert event.args[0] == 3
    assert event.args[2] == 0x1000
    assert event.result_int == 5


def test_error_maps_errno_to_name():
    """A failure ( = -1 Err#2) becomes ENOENT with success False."""
    event = _parse(r' 1871/0x45006d:  open("/nope\0", 0x0, 0x0)		 = -1 Err#2')

    assert event.result_int == -1
    assert event.error_name == "ENOENT"
    assert not event.success


def test_stat64_is_aliased_to_stat():
    """The BSD stat64 name maps to the stat handler name."""
    event = _parse(r' 1871/0x45006d:  stat64("/etc/hosts\0", 0x7fff, 0x0)		 = 0 0')

    assert event.syscall == "stat"
    assert event.args[0] == b"/etc/hosts"


def test_fork_return_is_child_pid():
    """A successful fork records the returned value as the child PID."""
    event = _parse(r" 1871/0x45006d:  fork()		 = 4321 0")

    assert event.syscall == "fork"
    assert event.child_pid == 4321


def test_rename_has_two_paths():
    """rename carries the old and new paths."""
    event = _parse(r' 1871/0x45006d:  rename("/a\0", "/b\0")		 = 0 0')

    assert event.syscall == "rename"
    assert event.args == [b"/a", b"/b"]


def test_header_line_is_ignored():
    """The dtruss column header is not a syscall line."""
    assert _parse("SYSCALL(args) \t\t = return") is None


def test_dtrace_diagnostic_is_ignored():
    """dtrace's own stderr diagnostics are skipped."""
    assert _parse("dtrace: system integrity protection is on") is None
