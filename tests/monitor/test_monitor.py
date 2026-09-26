"""Regression tests for Monitor internal cross-calls that passed a details dict
positionally instead of as **kwargs, raising TypeError when those branches ran.
"""

from lsoph.monitor import Monitor


def test_process_exit_closes_open_fds():
    """A process exiting with a still-open fd closes it (was a TypeError)."""
    monitor = Monitor(identifier="t")
    monitor.open(100, b"/a", 3, True, 1.0)

    monitor.process_exit(100, 2.0)

    info = monitor.files[b"/a"]
    assert info.status == "closed"
    assert not info.is_open


def test_rename_to_ignored_path_deletes_source():
    """Renaming a tracked file onto an ignored path deletes the source (was a TypeError)."""
    monitor = Monitor(identifier="t")
    monitor.open(100, b"/a", 3, True, 1.0)
    monitor.ignore(b"/ignored")

    monitor.rename(100, b"/a", b"/ignored", True, 2.0)

    assert monitor.files[b"/a"].status == "deleted"


def test_rename_path_to_itself_preserves_file_and_fd_state():
    """A successful no-op rename must not delete the tracked file."""
    monitor = Monitor(identifier="t")
    monitor.open(100, b"/a", 3, True, 1.0)

    monitor.rename(100, b"/a", b"/a", True, 2.0)

    info = monitor.files[b"/a"]
    assert info.status == "open"
    assert info.last_event_type == "RENAME"
    assert info.open_by_pids == {100: {3}}
    assert monitor.pid_fd_map == {100: {3: b"/a"}}


def test_file_reopened_on_a_std_fd_is_tracked_by_that_fd():
    """A real file opened onto fd 0 takes over from <STDIN> until closed."""
    monitor = Monitor(identifier="t")
    monitor.open(100, b"/a", 0, True, 1.0)

    monitor.read(100, 0, None, True, 2.0, bytes=5)
    monitor.close(100, 0, True, 3.0)

    info = monitor.files[b"/a"]
    assert info.bytes_read == 5
    assert info.status == "closed"
    assert info.open_by_pids == {}
    assert monitor.get_path(100, 0) == b"<STDIN>"
