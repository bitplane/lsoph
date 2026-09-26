"""Tests for lsoph.util.pid."""

import os
import socket
import subprocess
import time

import psutil
import pytest

from lsoph.util.pid import get_descendants, get_fd_path


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


def test_get_descendants_walks_the_whole_tree():
    shell = subprocess.Popen(["sh", "-c", "sleep 5 & sleep 5 & wait"])
    try:
        time.sleep(0.3)
        grandchildren = {c.pid for c in psutil.Process(shell.pid).children()}
        assert len(grandchildren) == 2

        found = get_descendants([os.getpid()])

        assert {shell.pid} | grandchildren <= found
        assert os.getpid() not in found
        assert get_descendants([shell.pid]) == grandchildren
    finally:
        shell.kill()
        for pid in grandchildren:
            psutil.Process(pid).kill()
        shell.wait()
