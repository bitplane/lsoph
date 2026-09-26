# Filename: src/lsoph/backend/fsusage/parse.py
"""
Parser for macOS `fs_usage -w` output lines.

Format (from the fs_usage source, system_cmds/fs_usage/fs_usage.c):

    HH:MM:SS.dddddd  <call>   [F=<fd>] [[<errno>]] [(<flags>)] [B=0x<hex>] <path>  <elapsed>[ W]  <command>.<threadid>

  - prefix:   printf("%s  %-17.17s", timestamp, sc_name)
  - fd:       " F=%-3d"           (also " F=%-3d[%3d]" when it errors)
  - errno:    "[%3d]"             (bracketed, space-padded)
  - bytes:    " B=0x%-6llx"
  - trailing: "%3llu.%06llu%s %s.%llu"  -> elapsed[ W] command.threadid

Paths are absolute and may contain spaces, so we anchor on the fixed timestamp
+ call at the front and elapsed + command.threadid at the back, and take the
path as everything from the first '/' in the middle. The trailing id is a
THREAD id (fs_usage -w prints no pid), which we use as the process key: correct
as long as a file's open/read/close happen on one thread.
"""

import logging
import os
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)

_LINE_RE = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d{6})\s+"
    r"(?P<call>\S+)\s+"
    r"(?P<body>.*)"
    r"\s+(?P<elapsed>\d+\.\d{6})(?:\s+W)?"
    r"\s+(?P<proc>.+)\.(?P<tid>\d+)\s*$"
)
_FD_RE = re.compile(r"F=(\d+)")
_ERRNO_RE = re.compile(r"\[\s*(\d+)\]")
_BYTES_RE = re.compile(r"B=0x([0-9a-fA-F]+)")

# macOS errno numbers -> names (subset relevant to file access). Only the name
# matters to the Monitor's ENOENT handling; unmapped ones keep the raw number.
_ERRNO_NAMES = {
    2: "ENOENT",
    13: "EACCES",
    17: "EEXIST",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    63: "ENAMETOOLONG",
}

# fs_usage call names -> normalized operation. The "_nocancel" suffix is stripped
# first (macOS emits open_nocancel, read_nocancel, ... for cancellation points).
_OPEN = {"open", "openat", "guarded_open_np"}
_CLOSE = {"close", "guarded_close_np"}
_READ = {"read", "pread", "readv"}
_WRITE = {"write", "pwrite", "writev"}
_STAT = {
    "stat64",
    "stat",
    "lstat64",
    "lstat",
    "fstat64",
    "fstatat64",
    "access",
    "faccessat",
    "getattrlist",
    "getattrlistat",
}
_DELETE = {"unlink", "unlinkat", "rmdir"}


def _op_for(call: str) -> str | None:
    name = call[: -len("_nocancel")] if call.endswith("_nocancel") else call
    if name in _OPEN:
        return "open"
    if name in _CLOSE:
        return "close"
    if name in _READ:
        return "read"
    if name in _WRITE:
        return "write"
    if name in _STAT:
        return "stat"
    if name in _DELETE:
        return "delete"
    return None


@dataclass
class FsEvent:
    """A normalized fs_usage event ready to apply to the Monitor."""

    op: str  # open / close / read / write / stat / delete
    tid: int  # thread id, used as the process key
    success: bool
    fd: int | None = None
    path: bytes | None = None
    byte_count: int = 0
    error_name: str | None = None


def parse_fsusage_line(line_str: str) -> FsEvent | None:
    """Parse one `fs_usage -w` line into an FsEvent, or None if not a tracked op."""
    match = _LINE_RE.match(line_str)
    if not match:
        return None

    op = _op_for(match.group("call"))
    if op is None:
        return None

    body = match.group("body")
    tid = int(match.group("tid"))

    # Path is the absolute path starting at the first '/' (F=/errno/flags/B=
    # fields never contain one). Search the fields only in what precedes it,
    # so a path like photo[12].jpg isn't read as errno 12.
    path = None
    fields = body
    slash = body.find("/")
    if slash != -1:
        path = os.fsencode(body[slash:].strip())
        fields = body[:slash]

    fd_match = _FD_RE.search(fields)
    fd = int(fd_match.group(1)) if fd_match else None

    errno_match = _ERRNO_RE.search(fields)
    if errno_match:
        errno = int(errno_match.group(1))
        error_name = _ERRNO_NAMES.get(errno, f"ERR#{errno}")
        success = False
    else:
        error_name = None
        success = True

    bytes_match = _BYTES_RE.search(fields)
    byte_count = int(bytes_match.group(1), 16) if bytes_match else 0

    return FsEvent(
        op=op,
        tid=tid,
        success=success,
        fd=fd,
        path=path,
        byte_count=byte_count,
        error_name=error_name,
    )
