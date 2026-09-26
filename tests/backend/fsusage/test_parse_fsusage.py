"""Tests for the macOS fs_usage output parser, from documented fs_usage -w lines."""

from lsoph.backend.fsusage.parse import parse_fsusage_line


def test_open_with_fd_and_path():
    """A successful open yields the returned fd and the absolute path."""
    line = (
        "08:02:07.011716  open     F=27   (_WC_T______X)  "
        "/Users/simon/auth.json.1284651536     0.000074   node.4017721"
    )
    event = parse_fsusage_line(line)

    assert event.op == "open"
    assert event.tid == 4017721
    assert event.fd == 27
    assert event.path == b"/Users/simon/auth.json.1284651536"
    assert event.success


def test_path_with_spaces_is_preserved():
    """fs_usage paths can contain spaces; the whole path is captured."""
    line = (
        "08:02:07.011111  lstat64                   "
        "/Users/simon/Library/Application Support/com.vercel.cli"
        "                                0.000006   node.4017721"
    )
    event = parse_fsusage_line(line)

    assert event.op == "stat"
    assert event.path == b"/Users/simon/Library/Application Support/com.vercel.cli"


def test_close_has_fd_no_path():
    """A close shows the fd but no path."""
    line = "08:02:07.019564  close    F=27      0.000013   node.4017721"
    event = parse_fsusage_line(line)

    assert event.op == "close"
    assert event.fd == 27
    assert event.path is None


def test_write_byte_count_is_hex():
    """B=0x… byte counts are decoded from hex."""
    line = "11:22:33.444555  write    F=24   B=0x190d      0.000100   proc.999"
    event = parse_fsusage_line(line)

    assert event.op == "write"
    assert event.fd == 24
    assert event.byte_count == 0x190D


def test_error_maps_errno_to_name():
    """A bracketed errno ([ 2]) becomes ENOENT with success False."""
    line = (
        "11:22:33.444555  open     [  2]     /etc/nonexistent      0.000010   cat.555"
    )
    event = parse_fsusage_line(line)

    assert event.op == "open"
    assert event.error_name == "ENOENT"
    assert not event.success
    assert event.fd is None
    assert event.path == b"/etc/nonexistent"


def test_wait_flag_is_tolerated():
    """A trailing 'W' (scheduled-out) after the elapsed time is handled."""
    line = "11:22:33.444555  read     F=5    B=0x1000      0.000050 W node.4017721"
    event = parse_fsusage_line(line)

    assert event.op == "read"
    assert event.fd == 5
    assert event.byte_count == 0x1000


def test_nocancel_variant_is_normalized():
    """open_nocancel is treated as an open."""
    line = (
        "11:22:33.444555  open_nocancel  F=8  (R_____)  "
        "/tmp/x      0.000020   proc.111"
    )
    event = parse_fsusage_line(line)

    assert event.op == "open"
    assert event.fd == 8


def test_disk_io_line_is_ignored():
    """Non-file events (disk I/O, etc.) are not tracked."""
    line = (
        "11:22:33.444555  RdData   D=0x1  B=0x1000  /dev/disk0      0.000010   kernel.0"
    )
    assert parse_fsusage_line(line) is None


def test_non_fsusage_line_returns_none():
    """A line that is not fs_usage output is skipped."""
    assert parse_fsusage_line("hello world") is None


def test_brackets_and_fields_in_the_path_are_not_parsed_as_fields():
    """photo[12].jpg is a filename, not errno 12; F=/B= in a path aren't fields."""
    line = (
        "08:02:07.011716  open     F=3    (R___________)  "
        "/Users/me/photo[12] F=9 B=0x10.jpg     0.000074   Preview.4017721"
    )
    event = parse_fsusage_line(line)

    assert event.success
    assert event.error_name is None
    assert event.fd == 3
    assert event.byte_count == 0
    assert event.path == b"/Users/me/photo[12] F=9 B=0x10.jpg"
