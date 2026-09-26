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


def test_recreating_a_deleted_path_clears_deleted():
    """Delete-then-recreate (editor saves, log rotation) is live again."""
    monitor = Monitor(identifier="t")
    monitor.open(100, b"/a", 3, True, 1.0)
    monitor.close(100, 3, True, 2.0)
    monitor.delete(100, b"/a", True, 3.0)

    monitor.open(100, b"/a", 3, True, 4.0)

    assert monitor.files[b"/a"].status == "open"


def test_successful_stat_of_a_deleted_path_clears_deleted():
    monitor = Monitor(identifier="t")
    monitor.stat(100, b"/a", True, 1.0)
    monitor.delete(100, b"/a", True, 2.0)

    monitor.stat(100, b"/a", True, 3.0)

    assert monitor.files[b"/a"].status == "accessed"


def test_rename_onto_an_open_file_keeps_both_fds_open():
    """Renaming e over an open f leaves f open via both fds."""
    monitor = Monitor(identifier="t")
    monitor.open(100, b"/e", 7, True, 1.0)
    monitor.open(100, b"/f", 8, True, 2.0)

    monitor.rename(100, b"/e", b"/f", True, 3.0)
    monitor.close(100, 7, True, 4.0)

    info = monitor.files[b"/f"]
    assert b"/e" not in monitor.files
    assert info.status == "open"
    assert info.open_by_pids == {100: {8}}

    monitor.close(100, 8, True, 5.0)
    assert info.status == "closed"


def test_rename_records_one_history_entry():
    monitor = Monitor(identifier="t")
    monitor.open(100, b"/c", 3, True, 1.0)

    monitor.rename(100, b"/c", b"/d", True, 2.0)

    renames = [e for e in monitor.files[b"/d"].event_history if e["type"] == "RENAME"]
    assert len(renames) == 1
    assert renames[0]["details"]["renamed_from"] == b"/c"


def test_std_streams_can_be_ignored_but_ignore_all_keeps_them():
    monitor = Monitor(identifier="t")
    monitor.write(100, 1, None, True, 1.0, bytes=3)
    monitor.write(100, 2, None, True, 1.0, bytes=3)
    monitor.open(100, b"/a", 3, True, 1.0)

    monitor.ignore_all()
    assert set(monitor.files) == {b"<STDOUT>", b"<STDERR>"}

    monitor.ignore(b"<STDOUT>")
    monitor.write(100, 1, None, True, 2.0, bytes=3)
    assert set(monitor.files) == {b"<STDERR>"}


def test_unresolvable_fd_is_looked_up_once_until_reopened(monkeypatch):
    import pytest

    import lsoph.monitor._monitor as monitor_module

    lookups = []

    def fake_get_fd_path(pid, fd):
        lookups.append((pid, fd))
        raise KeyError("socket")

    monkeypatch.setattr(monitor_module, "get_fd_path", fake_get_fd_path)
    monitor = Monitor(identifier="t")

    for _ in range(3):
        with pytest.raises(KeyError):
            monitor.read(100, 9, None, True, 1.0, bytes=1)
    assert lookups == [(100, 9)]

    # Closing and reusing the fd number for a real file resets it.
    monitor.close(100, 9, True, 2.0)
    monitor.open(100, b"/a", 9, True, 3.0)
    monitor.read(100, 9, None, True, 4.0, bytes=1)
    assert monitor.files[b"/a"].bytes_read == 1
