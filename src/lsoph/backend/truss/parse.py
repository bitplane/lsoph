# Filename: src/lsoph/backend/truss/parse.py
"""
Parser for FreeBSD truss output lines.

truss (unlike strace) prints one complete line per syscall on return, so there
is no unfinished/resumed splicing. Its argument syntax matches strace's, so the
argument grammar is reused; only the line prefix, return value and error forms
differ. Format (from truss(1) / usr.bin/truss source):

    34233: openat(AT_FDCWD,"/dev/urandom",O_RDONLY,00) = 24 (0x18)
    34233: open("/x",O_RDONLY,00) ERR#2 'No such file or directory'
    34233: SIGNAL 17 (SIGCHLD)
    34233: process exit, rval = 0

The PID prefix is "%5d: " (right-justified, so small PIDs get leading spaces).
"""

import logging
import re

import pyparsing as pp

from ..strace.parser_defs import number, param_list, syscall_name
from ..strace.syscall import PROCESS_SYSCALLS, Syscall

log = logging.getLogger(__name__)

# "  123: rest" -> pid, rest
_PID_RE = re.compile(r"^\s*(\d+):\s*(.*)$", re.DOTALL)
_RVAL_RE = re.compile(r"rval\s*=\s*(-?\d+)")

# FreeBSD errno numbers -> names (subset relevant to file access). truss prints
# the number, not the symbolic name; the Monitor keys ENOENT handling off the
# name, so at least that one must be mapped.
_ERRNO_NAMES = {
    2: "ENOENT",
    9: "EBADF",
    13: "EACCES",
    20: "ENOTDIR",
    21: "EISDIR",
    22: "EINVAL",
    30: "EROFS",
    40: "ELOOP",
    63: "ENAMETOOLONG",
}

# FreeBSD syscall names -> the handler names used by SYSCALL_HANDLERS.
_NAME_ALIASES = {
    "fstatat": "newfstatat",
    "pread": "pread64",
    "pwrite": "pwrite64",
}

_LPAREN, _RPAREN = pp.Suppress("("), pp.Suppress(")")
# " = 24 (0x18)": capture the decimal; the hex form is redundant.
_result_ok = (
    pp.Suppress("=")
    + number("result_val")
    + pp.Suppress("(")
    + number
    + pp.Suppress(")")
)
# " ERR#2 'No such file or directory'"
_result_err = (
    pp.Suppress(pp.Literal("ERR#"))
    + pp.Word(pp.nums)("errno")
    + pp.QuotedString("'")("error_msg")
)
_truss_line = (
    syscall_name
    + _LPAREN
    + param_list
    + _RPAREN
    + (_result_ok | _result_err)
    + pp.StringEnd()
)
_truss_line.parseWithTabs()


def _extract_args(parsed: pp.ParseResults) -> list:
    args = []
    if "args" in parsed and parsed.args:
        for group in parsed.args:
            if isinstance(group, pp.ParseResults):
                if len(group) == 2:  # key=value
                    args.append(group[1])
                elif len(group) == 1:  # standalone value
                    args.append(group[0])
            else:
                args.append(str(group))
    return args


def parse_truss_line(line_str: str, timestamp: float) -> Syscall | None:
    """Parse one truss output line into a Syscall, or None if it is not one."""
    match = _PID_RE.match(line_str)
    if not match:
        return None  # No PID prefix (truss -f prefixes every line).
    pid = int(match.group(1))
    body = match.group(2).rstrip()
    raw = line_str.encode("utf-8", "surrogateescape")

    if body.startswith("SIGNAL"):
        return None

    if body.startswith("process exit"):
        rval_match = _RVAL_RE.search(body)
        rval = int(rval_match.group(1)) if rval_match else 0
        return Syscall(
            pid=pid,
            syscall="exit",
            result_int=rval,
            result_str=str(rval),
            timestamp=timestamp,
            raw_line=raw,
        )

    try:
        parsed = _truss_line.parseString(body, parseAll=True)
    except pp.ParseException:
        log.debug(f"truss line did not parse: {line_str!r}")
        return None

    name = _NAME_ALIASES.get(parsed.syscall, parsed.syscall)
    args = _extract_args(parsed)

    if "errno" in parsed:
        errno = int(parsed.errno)
        error_name = _ERRNO_NAMES.get(errno, f"ERR#{errno}")
        error_msg = parsed.error_msg
        result_int = -1
        result_str = "-1"
    else:
        error_name = None
        error_msg = None
        result_int = parsed.result_val
        result_str = str(result_int)

    child_pid = None
    if (
        name in PROCESS_SYSCALLS
        and error_name is None
        and result_int is not None
        and result_int > 0  # the child's own fork() returns 0
    ):
        child_pid = result_int

    return Syscall(
        pid=pid,
        syscall=name,
        args=args,
        result_int=result_int,
        result_str=result_str,
        child_pid=child_pid,
        error_name=error_name,
        error_msg=error_msg,
        timestamp=timestamp,
        raw_line=raw,
    )
