# Filename: src/lsoph/backend/ktrace/parse.py
"""
Parser for BSD kdump output.

Unlike the single-line tracers, kdump decodes a ktrace dump into multiple
records per syscall, so parsing is stateful per PID:

    517 ls  CALL  open(0x7fff...,0x0,0x0)   <- syscall entry, args as hex/numbers
    517 ls  NAMI  "/etc/hosts"              <- resolved pathname argument(s)
    517 ls  RET   open 3                     <- return value (and "errno N" on error)

A CALL starts a pending syscall for the PID; NAMI records supply the resolved
paths (which replace the corresponding pointer arguments); RET completes it and
yields a Syscall. Since it is syscall-level, the resulting Syscall dispatches
through the shared handlers. (Format verified against kdump(1); the record set
matches FreeBSD -- OpenBSD/NetBSD differ slightly and need a real-host check.)
"""

import logging
import re

from ..strace.syscall import EXIT_SYSCALLS, PROCESS_SYSCALLS, Syscall

log = logging.getLogger(__name__)

# "<pid> <prog> <TYPE> <data>"
_LINE_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<prog>\S+)\s+(?P<type>[A-Z]+)\s+(?P<data>.*)$"
)
_CALL_RE = re.compile(r"^(?P<call>\w+)(?:\((?P<args>.*)\))?\s*$")
# Returns above 9 carry a hex copy: "RET read 100/0x64".
_RET_RE = re.compile(
    r"^(?P<call>\w+)\s+(?P<ret>-?\d+)(?:/0x[0-9a-fA-F]+)?(?:\s+errno\s+(?P<errno>\d+).*)?\s*$"
)
_NAMI_RE = re.compile(r'^"(?P<path>.*)"\s*$')

_ERRNO_NAMES = {
    2: "ENOENT",
    9: "EBADF",
    13: "EACCES",
    17: "EEXIST",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    63: "ENAMETOOLONG",
}

_NAME_ALIASES = {
    "fstatat": "newfstatat",
    "pread": "pread64",
    "pwrite": "pwrite64",
}

# For each syscall, which argument positions are pathnames (and so get replaced,
# in order, by the NAMI records).
_PATH_ARGS = {
    "open": [0],
    "openat": [1],
    "creat": [0],
    "stat": [0],
    "lstat": [0],
    "access": [0],
    "fstatat": [1],
    "unlink": [0],
    "unlinkat": [1],
    "rmdir": [0],
    "rename": [0, 1],
    "renameat": [1, 3],
    "chdir": [0],
}


def _split_args(s: str) -> list:
    """Split a kdump CALL argument list. Args are hex/decimal/symbolic (no
    strings -- pathnames come as separate NAMI records)."""
    if not s or not s.strip():
        return []
    out: list = []
    for tok in s.split(","):
        tok = tok.strip()
        try:
            out.append(int(tok, 16) if tok.lower().startswith("0x") else int(tok))
        except ValueError:
            out.append(tok)  # symbolic constant (e.g. AT_FDCWD)
    return out


class KdumpParser:
    """Stateful parser: feed kdump lines, get Syscall objects on completion."""

    def __init__(self):
        # pid -> {"syscall": str, "args": list, "namis": list[bytes]}
        self._pending: dict[int, dict] = {}

    def feed(self, line_str: str, timestamp: float) -> Syscall | None:
        match = _LINE_RE.match(line_str)
        if not match:
            return None
        pid = int(match.group("pid"))
        record = match.group("type")
        data = match.group("data")

        if record == "CALL":
            call = _CALL_RE.match(data)
            if not call:
                return None
            name = call.group("call")
            # An exit has no RET record; emit it immediately.
            if name in EXIT_SYSCALLS:
                self._pending.pop(pid, None)
                return Syscall(pid=pid, syscall=name, timestamp=timestamp)
            self._pending[pid] = {
                "syscall": name,
                "args": _split_args(call.group("args") or ""),
                "namis": [],
            }
            return None

        if record == "NAMI":
            pending = self._pending.get(pid)
            nami = _NAMI_RE.match(data)
            if pending is not None and nami is not None:
                pending["namis"].append(
                    nami.group("path").encode("utf-8", "surrogateescape")
                )
            return None

        if record == "RET":
            ret = _RET_RE.match(data)
            pending = self._pending.pop(pid, None)
            if (
                ret is None
                or pending is None
                or pending["syscall"] != ret.group("call")
            ):
                return None
            return self._build(pid, pending, ret, timestamp)

        return None  # GIO, PSIG, CSW, ... are ignored.

    def _build(self, pid, pending, ret, timestamp) -> Syscall:
        name = pending["syscall"]
        args = list(pending["args"])
        namis = pending["namis"]

        # Replace pointer arguments with the resolved NAMI paths, in order.
        for i, idx in enumerate(_PATH_ARGS.get(name, [])):
            if i >= len(namis):
                break
            if idx < len(args):
                args[idx] = namis[i]
            elif idx == len(args):
                args.append(namis[i])

        name = _NAME_ALIASES.get(name, name)
        ret_val = int(ret.group("ret"))
        errno = ret.group("errno")
        error_name = _ERRNO_NAMES.get(int(errno), f"ERR#{errno}") if errno else None

        child_pid = None
        if name in PROCESS_SYSCALLS and error_name is None and ret_val > 0:
            child_pid = ret_val

        return Syscall(
            pid=pid,
            syscall=name,
            args=args,
            result_int=ret_val,
            result_str=str(ret_val),
            child_pid=child_pid,
            error_name=error_name,
            timestamp=timestamp,
        )
