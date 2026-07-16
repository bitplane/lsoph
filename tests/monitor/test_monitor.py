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
