"""Tests for lsoph.util.pid."""

import os
import socket

import pytest

from lsoph.util.pid import get_fd_path


def test_get_fd_path_raises_keyerror_for_nonexistent_pid():
    """A PID that does not exist yields KeyError."""
    with pytest.raises(KeyError):
        get_fd_path(2_000_000_000, 3)


def test_get_fd_path_raises_keyerror_not_psutil_error():
    """PID 1 exists but its fds are unreadable to a normal user; the failure must
    surface as KeyError, not a leaked psutil AccessDenied."""
    with pytest.raises(KeyError):
        get_fd_path(1, 999_999)


def test_get_fd_path_resolves_files_and_rejects_non_files(tmp_path):
    target = tmp_path / "f"
    with open(target, "w") as f, socket.socket() as s:
        assert get_fd_path(os.getpid(), f.fileno()) == bytes(target)
        with pytest.raises(KeyError):
            get_fd_path(os.getpid(), s.fileno())
