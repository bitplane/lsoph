# Filename: src/lsoph/backend/strace/parse.py
"""
Strace output parser using the pyparsing library.
Parses decoded strace lines (UTF-8 with surrogateescape).
Yields Syscall objects with parsed arguments (int/str). Handles missing PIDs on initial process lines.
"""

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from typing import Any, List, Optional

import pyparsing as pp

from lsoph.log import TRACE_LEVEL_NUM
from lsoph.monitor import Monitor

from .parser_defs import (
    parse_line,
    split_exit_marker,
    split_resumed,
    split_unfinished,
)
from .syscall import PROCESS_SYSCALLS, Syscall

log = logging.getLogger(__name__)


def _build_syscall_object(
    pid: int,
    syscall_name_str: str,
    args_list: List[Any],
    result_data: dict,
    timestamp: float,
    raw_line_bytes: bytes,
) -> Syscall:
    """Helper to create Syscall object, parsing result and child PID."""

    # Args list is already extracted with correct types
    args_parsed_list = args_list

    result_val = result_data.get("result_val")  # Already parsed type (int or '?')
    error_name = result_data.get("error_name")
    error_msg = result_data.get("error_msg")
    timing = result_data.get("timing")

    # Determine result_int and result_str based on parsed result_val
    result_int: Optional[int] = None
    result_str: Optional[str] = None
    if isinstance(result_val, int):
        result_int = result_val
        result_str = str(result_val)  # Convert int back to str for result_str
    elif result_val == "?":
        result_str = "?"
    # Handle potential None case, though parser should return int or '?'
    elif result_val is not None:
        result_str = str(result_val)

    child_pid = None
    if (
        syscall_name_str in PROCESS_SYSCALLS
        and not error_name
        and result_int is not None  # Check result_int
        and result_int >= 0
    ):
        child_pid = result_int

    return Syscall(
        pid=pid,
        syscall=syscall_name_str,
        args=args_parsed_list,  # Store list of parsed values (int/str)
        result_str=result_str,  # Store string representation
        result_int=result_int,  # Store integer representation if applicable
        child_pid=child_pid,
        error_name=error_name,
        error_msg=error_msg,
        timing=timing,
        timestamp=timestamp,
        raw_line=raw_line_bytes,  # Store original bytes
    )


async def parse_strace_stream_pyparsing(
    lines_bytes: AsyncIterator[bytes],  # Accepts bytes lines
    monitor: Monitor,  # Keep monitor arg for signature consistency
    stop_event: asyncio.Event,
    syscalls: list[str] | None = None,  # Keep syscalls arg for signature consistency
    attach_ids: list[int] | None = None,  # Pass initial PIDs if attaching
) -> AsyncIterator[Syscall]:  # Keep return type hint for consistency
    """
    Asynchronously parses a stream of raw strace output bytes lines into Syscall objects
    using pyparsing. Decodes lines before parsing. Handles missing PIDs.
    """

    line_count = 0
    parsed_count = 0
    trace_enabled = log.isEnabledFor(TRACE_LEVEL_NUM)
    # Track last known PID for lines potentially missing it.
    current_pid: int | None = None
    # Pending "<unfinished ...>" prefixes, keyed by PID (one blocked call per PID).
    unfinished_calls: dict[int, str] = {}
    # If attaching to a single known PID initially, use that as default
    if attach_ids and len(attach_ids) == 1:
        current_pid = attach_ids[0]
        log.debug(f"Setting initial PID context to {current_pid} (attach mode)")
    try:
        async for line_b in lines_bytes:
            line_count += 1
            if stop_event.is_set():
                break

            if trace_enabled:
                log.log(TRACE_LEVEL_NUM, f"Raw strace line: {line_b!r}")

            # Decode line using surrogateescape
            try:
                line_str = line_b.decode("utf-8", "surrogateescape")
            except Exception as decode_err:
                log.error(
                    f"Failed to decode strace line: {decode_err}. Bytes: {line_b!r}"
                )
                continue  # Skip this line

            event_timestamp = time.time()  # Use current time as timestamp

            exited = split_exit_marker(line_str)
            if exited is not None:
                exit_pid = exited[0] if exited[0] is not None else current_pid
                log.debug(f"PID {exit_pid}: {exited[1]}")
                if exit_pid is not None:
                    # Report it as the exit it was, so fds get closed.
                    parsed_count += 1
                    yield Syscall(
                        pid=exit_pid,
                        syscall="exit_group",
                        timestamp=event_timestamp,
                        raw_line=line_b,
                    )
                continue

            # --- Handle split syscalls (strace -f interleaving) ---
            unfinished = split_unfinished(line_str)
            if unfinished is not None:
                u_pid, prefix = unfinished
                key_pid = u_pid if u_pid is not None else current_pid
                if key_pid is not None:
                    current_pid = key_pid
                    unfinished_calls[key_pid] = prefix
                else:
                    log.debug(f"Unfinished line with no PID context: {line_str!r}")
                continue  # Wait for the matching 'resumed' line.

            resumed = split_resumed(line_str)
            if resumed is not None:
                r_pid, _name, rest = resumed
                key_pid = r_pid if r_pid is not None else current_pid
                prefix = unfinished_calls.pop(key_pid, None) if key_pid else None
                if prefix is None:
                    log.debug(f"Resumed line with no pending call: {line_str!r}")
                    continue
                current_pid = key_pid
                # Splice the halves back into a complete line and parse normally.
                line_str = f"{key_pid} {prefix}{rest}"
                line_b = line_str.encode("utf-8", "surrogateescape")

            try:
                # --- Try parsing as a complete syscall line first ---
                parsed = parse_line(line_str)  # Use the stricter parser

                # --- Determine PID ---
                pid_from_line: int | None = parsed.get("pid")  # Optional PID
                if pid_from_line is not None:
                    pid = pid_from_line
                    current_pid = pid  # Remember the last PID we saw explicitly
                elif current_pid is not None:
                    # If PID is missing, use the last known PID
                    log.debug(
                        f"Line missing PID, using last known PID: {current_pid}. Line: {line_str!r}"
                    )
                    pid = current_pid
                else:
                    # PID missing and no previous PID known (e.g., first line)
                    log.warning(
                        f"Line missing PID and no previous PID known. Cannot process line: {line_str!r}"
                    )
                    continue  # Skip line if PID cannot be determined

                # --- Extract data from the 'syscall_complete' group ---
                syscall_data = parsed.syscall_complete
                syscall_name_str = syscall_data.syscall
                result_val = syscall_data.result_val  # Already parsed type

                # Extract error and timing if present
                result_data = {
                    "result_val": result_val,
                    "error_name": (
                        syscall_data.error_part[0]
                        if "error_part" in syscall_data
                        else None
                    ),
                    "error_msg": (
                        syscall_data.error_part[1]
                        if "error_part" in syscall_data
                        else None
                    ),
                    "timing": (
                        syscall_data.timing_part[0]
                        if "timing_part" in syscall_data
                        else None
                    ),
                }

                # Extract arguments (already parsed types)
                args_parsed_list = []
                if "args" in syscall_data and syscall_data.args:
                    for arg_group in syscall_data.args:
                        if isinstance(arg_group, pp.ParseResults):
                            if len(arg_group) == 2:  # key=value pair
                                args_parsed_list.append(arg_group[1])
                            elif len(arg_group) == 1:  # Standalone value
                                args_parsed_list.append(arg_group[0])
                        else:  # Should not happen
                            args_parsed_list.append(str(arg_group))  # Fallback

                syscall_obj = _build_syscall_object(
                    pid,
                    syscall_name_str,
                    args_parsed_list,  # Pass the extracted list
                    result_data,
                    event_timestamp,
                    line_b,
                )
                log.debug(f"Parsed complete event: {syscall_obj!r}")  # Use repr

            except pp.ParseException:
                # Not a complete syscall line (signal, exit marker, etc.).
                log.debug(f"Line did not parse as complete syscall: {line_str!r}")
                syscall_obj = None

            except Exception as e:
                log.exception(
                    f"Error processing parsed pyparsing result for line {line_str!r}: {e}"
                )
                syscall_obj = None

            # Yield the successfully parsed object if it matches filter
            if syscall_obj and (syscalls is None or syscall_obj.syscall in syscalls):
                parsed_count += 1
                yield syscall_obj

            await asyncio.sleep(0)  # Yield control more frequently

    except asyncio.CancelledError:
        log.info("Strace stream parsing task cancelled.")
    finally:
        log.info(
            f"Exiting pyparsing strace stream parser. Processed {line_count} lines, yielded {parsed_count} events."
        )
        if unfinished_calls:
            log.debug(f"Parser exiting with unfinished calls: {unfinished_calls}")
