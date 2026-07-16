"""Tests for the Linux /proc/<pid>/fd reader used by the psutil backend.

psutil.open_files() reports regular files only, so device files a process holds
open are invisible to it; _fd_paths_from_proc reads the fd symlinks directly to
cover them. Run against our own process, so the expected fds are known.
"""

import os
import sys

import pytest

from lsoph.backend.psutil.helpers import _fd_paths_from_proc

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="/proc/<pid>/fd is Linux-only"
)


def test_device_file_held_open_is_reported():
    """A held-open /dev/zero (a device, not a regular file) is captured."""
    fd = os.open("/dev/zero", os.O_RDONLY)

    try:
        paths = {entry["path"] for entry in _fd_paths_from_proc(os.getpid())}
    finally:
        os.close(fd)

    assert b"/dev/zero" in paths


def test_access_mode_comes_from_the_fd_symlink():
    """A write-only fd is reported with a writable, non-readable mode."""
    fd = os.open("/dev/null", os.O_WRONLY)

    try:
        entry = next(e for e in _fd_paths_from_proc(os.getpid()) if e["fd"] == fd)
    finally:
        os.close(fd)

    assert entry["path"] == b"/dev/null"
    assert "w" in entry["mode"]
    assert "r" not in entry["mode"]


def test_pipes_and_sockets_are_skipped():
    """Non-filesystem fds (a pipe) are not reported as files."""
    read_fd, write_fd = os.pipe()

    try:
        entries = _fd_paths_from_proc(os.getpid())
    finally:
        os.close(read_fd)
        os.close(write_fd)

    assert all(not e["path"].startswith(b"pipe:") for e in entries)
    assert all(e["fd"] not in (read_fd, write_fd) for e in entries)
