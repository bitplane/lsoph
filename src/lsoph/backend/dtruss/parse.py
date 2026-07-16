# Filename: src/lsoph/backend/dtruss/parse.py
"""
Parser for macOS/BSD dtruss output lines.

dtruss (a DTrace script) is syscall-level like strace/truss, with the same
argument positions, so parsed lines reuse the shared syscall handlers. It
differs only in surface format (verified against the dtruss source):

  - prefix (with -f):  "%5d/0x%x:  "   -> "<pid>/0x<tid>:  "  (real pid, hex tid)
  - args:              strings as "..."; other args as 0xHEX or decimal
  - return + errno:    " = %d %s%d"    -> " = <ret> <errno>"  (success)
                                          " = -1 Err#<errno>" (failure)

Example lines (dtruss -f):
   1871/0x45006d:  open("/etc/hosts\\0", 0x0, 0x0)         = 3 0
   1871/0x45006d:  read(0x3, "data", 0x1000)               = 100 0
   1871/0x45006d:  open("/nope\\0", 0x0, 0x0)              = -1 Err#2
"""

import logging
import re

from lsoph.util.string import c_str_to_bytes

from ..strace.syscall import PROCESS_SYSCALLS, Syscall

log = logging.getLogger(__name__)

# "<pid>/0x<tid>:  <rest>"  (pid is right-justified with spaces)
_LINE_RE = re.compile(
    r"^\s*(?P<pid>\d+)/0x[0-9a-fA-F]+:\s+"
    r"(?P<call>\w+)\((?P<args>.*)\)\s*=\s*"
    r"(?P<ret>-?\d+|0x[0-9a-fA-F]+)\s+(?:Err#)?(?P<errno>\d+)\s*$"
)

# BSD/macOS errno numbers -> names (subset relevant to file access).
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

# dtruss/BSD syscall names -> the handler names used by SYSCALL_HANDLERS.
_NAME_ALIASES = {
    "stat64": "stat",
    "lstat64": "lstat",
    "fstatat64": "newfstatat",
    "pread": "pread64",
    "pwrite": "pwrite64",
}


def _parse_int(token: str) -> int:
    token = token.strip()
    return int(token, 16) if token.lower().startswith("0x") else int(token)


def _split_args(s: str) -> list:
    """Split a dtruss argument list, keeping quoted strings (which may contain
    commas) intact. String args become bytes; numeric args become ints."""
    args: list = []
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] in ", ":
            i += 1
        if i >= n:
            break
        if s[i] == '"':
            j = i + 1
            chars = []
            while j < n:
                if s[j] == "\\" and j + 1 < n:
                    chars.append(s[j : j + 2])
                    j += 2
                    continue
                if s[j] == '"':
                    break
                chars.append(s[j])
                j += 1
            raw = "".join(chars)
            try:
                value = c_str_to_bytes(raw).rstrip(b"\x00")
            except Exception:
                value = raw.encode("utf-8", "surrogateescape")
            args.append(value)
            i = j + 1
        else:
            j = i
            while j < n and s[j] != ",":
                j += 1
            token = s[i:j].strip()
            try:
                args.append(_parse_int(token))
            except ValueError:
                args.append(token)
            i = j
    return args


def parse_dtruss_line(line_str: str, timestamp: float) -> Syscall | None:
    """Parse one dtruss output line into a Syscall, or None if it is not one."""
    match = _LINE_RE.match(line_str)
    if not match:
        return None

    pid = int(match.group("pid"))
    call = match.group("call")
    if call.endswith("_nocancel"):
        call = call[: -len("_nocancel")]
    name = _NAME_ALIASES.get(call, call)

    args = _split_args(match.group("args"))
    errno = int(match.group("errno"))
    result_int = _parse_int(match.group("ret"))

    if errno != 0:
        error_name = _ERRNO_NAMES.get(errno, f"ERR#{errno}")
    else:
        error_name = None

    child_pid = None
    if name in PROCESS_SYSCALLS and error_name is None and result_int > 0:
        child_pid = result_int

    return Syscall(
        pid=pid,
        syscall=name,
        args=args,
        result_int=result_int,
        result_str=str(result_int),
        child_pid=child_pid,
        error_name=error_name,
        error_msg=None,
        timestamp=timestamp,
        raw_line=line_str.encode("utf-8", "surrogateescape"),
    )
