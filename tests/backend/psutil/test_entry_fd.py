"""Tests for _entry_fd, which keys open-files entries for snapshot diffing.

On Windows psutil reports files with fd == -1 (NT handles, not POSIX fds);
without a pseudo-fd every file on Windows would be skipped.
"""

from lsoph.backend.psutil.backend import _entry_fd


def test_real_fd_is_used_directly():
    """A POSIX entry with a real fd keys on that fd."""
    entry = {"fd": 7, "path": b"/tmp/a", "type": "file"}

    assert _entry_fd(entry) == 7


def test_windows_file_without_fd_gets_a_stable_pseudo_fd():
    """A file entry with fd == -1 (Windows) keys on its path, stably."""
    entry = {"fd": -1, "path": b"C:\\py\\held_open.txt", "type": "file"}

    first = _entry_fd(entry)
    second = _entry_fd(dict(entry))

    assert first is not None and first >= 0
    assert first == second


def test_socket_without_fd_is_skipped():
    """A socket entry with fd == -1 still returns None (skipped)."""
    entry = {"fd": -1, "path": b"<SOCKET:TCP:1.2.3.4:5>", "type": "socket"}

    assert _entry_fd(entry) is None
