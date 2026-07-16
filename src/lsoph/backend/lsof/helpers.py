# Filename: src/lsoph/backend/lsof/helpers.py
"""Helper functions for the lsof backend. Works with bytes paths."""

import asyncio
import logging
import shutil
from collections.abc import AsyncIterator

from lsoph.log import TRACE_LEVEL_NUM

from ..polling import OpenFile, PidFiles, Snapshot
from .parse import _parse_lsof_f_output

log = logging.getLogger(__name__)  # Use specific logger

# Timeout for waiting for lsof command (prevent hangs)
LSOF_COMMAND_TIMEOUT = 10.0


# --- Async I/O Logic ---


# Define helper function outside the main try block
async def _read_stream(
    stream: asyncio.StreamReader | None,
    stream_name: str,
    process_pid: int | str,
    timeout: float,
) -> list[bytes]:  # Returns list of bytes
    """Reads lines (as bytes) from a stream with a timeout."""
    lines: list[bytes] = []  # Store bytes
    if not stream:
        return lines
    while True:
        try:
            # Use wait_for for readline to prevent hangs on the stream read itself
            line_bytes = await asyncio.wait_for(stream.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            # Log timeout reading the stream, but the process might still finish
            log.error(f"Timeout reading {stream_name} from lsof (PID {process_pid}).")
            # Don't kill the process here, let the outer timeout handle it
            # if the process itself hangs.
            break  # Stop reading this stream
        except asyncio.IncompleteReadError as read_err:
            # Can happen if process exits while reading
            log.debug(f"Incomplete read from lsof {stream_name}: {read_err}")
            break
        except Exception as read_err:
            log.error(f"Error reading lsof {stream_name}: {read_err}")
            break  # Stop reading on other errors

        if not line_bytes:
            break  # EOF reached
        # Append raw bytes, stripping only trailing newline bytes if present
        if line_bytes.endswith(b"\n"):
            lines.append(line_bytes[:-1])
        elif line_bytes.endswith(b"\r\n"):
            lines.append(line_bytes[:-2])
        else:
            lines.append(line_bytes)
        # DO NOT DECODE HERE
    return lines


async def _run_lsof_command_async(
    pids: list[int] | None = None,
) -> AsyncIterator[bytes]:  # Yields bytes
    """
    Runs the lsof command asynchronously and yields its raw standard output lines as bytes.
    Handles potential hangs using a timeout.
    """
    lsof_path = shutil.which("lsof")
    if not lsof_path:
        raise FileNotFoundError("lsof command not found in PATH")

    # Base command: -n (no host resolution), -P (no port resolution), -F pcftn (parseable output)
    # Added +c 0 to show full command names
    # Added +L to prevent listing link counts (can be slow)
    # Use bytes for command parts that might interact with filesystem directly if needed,
    # though usually exec takes strings. Sticking with strings for cmd list itself.
    cmd = [lsof_path, "-n", "-P", "+c", "0", "+L", "-F", "pcftn"]
    if pids:
        # Filter out non-positive PIDs just in case
        valid_pids = [str(p) for p in pids if p > 0]
        if not valid_pids:
            log.warning("lsof called with no valid PIDs to monitor.")
            # Use a bare return to stop the async generator, yielding nothing.
            return

        cmd.extend(["-p", ",".join(valid_pids)])
        log.debug(f"Running lsof for PIDs: {valid_pids}")
    else:
        # If no PIDs specified, maybe log a warning or raise error?
        # For now, let it run system-wide (potentially slow/resource intensive)
        log.warning("Running lsof without specific PIDs (system-wide).")

    process: asyncio.subprocess.Process | None = None
    try:
        log.debug(f"Executing lsof command: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,  # Capture stderr as well
        )
        process_pid_str = str(process.pid) if process.pid else "N/A"
        log.debug(f"lsof process started with PID: {process_pid_str}")

        # Wait for the process and stream readers to complete, with an overall timeout
        try:
            # Pass necessary info to the helper function
            read_timeout = LSOF_COMMAND_TIMEOUT / 2
            # _read_stream now returns list[bytes]
            stdout_task = asyncio.create_task(
                _read_stream(process.stdout, "stdout", process_pid_str, read_timeout)
            )
            stderr_task = asyncio.create_task(
                _read_stream(process.stderr, "stderr", process_pid_str, read_timeout)
            )
            process_wait_task = asyncio.create_task(process.wait())

            # Wait for all tasks (streams reading + process exit)
            done, pending = await asyncio.wait(
                [stdout_task, stderr_task, process_wait_task],
                timeout=LSOF_COMMAND_TIMEOUT,
                return_when=asyncio.ALL_COMPLETED,
            )

            # Check if the process itself timed out (didn't complete)
            if process_wait_task not in done:
                log.error(
                    f"lsof command (PID {process_pid_str}) timed out after {LSOF_COMMAND_TIMEOUT}s."
                )
                # Cancel pending stream readers
                for task in pending:
                    if (
                        task is not process_wait_task
                    ):  # Don't cancel the wait task itself
                        task.cancel()
                        try:
                            await task  # Allow cancellation to propagate
                        except asyncio.CancelledError:
                            pass
                # Kill the hung process
                if process.returncode is None:
                    log.warning(f"Killing timed-out lsof process {process_pid_str}")
                    try:
                        process.kill()
                        await process.wait()  # Wait for kill confirmation
                    except ProcessLookupError:
                        pass  # Already gone
                    except Exception as kill_e:
                        log.error(f"Error killing timed-out lsof process: {kill_e}")
                raise TimeoutError("lsof command timed out")  # Signal timeout to caller

            # Process finished within timeout, get results (as bytes)
            stdout_lines_bytes: list[bytes] = await stdout_task
            stderr_lines_bytes: list[bytes] = await stderr_task
            return_code = await process_wait_task  # Get exit code

            # Log stderr if any content was captured (decode for logging)
            if stderr_lines_bytes:
                stderr_str = "\n".join(
                    b.decode("utf-8", "replace") for b in stderr_lines_bytes
                )
                log.debug(
                    f"lsof stderr (PID {process_pid_str}, Exit Code {return_code}):\n"
                    + stderr_str
                )

            # Yield stdout lines (as bytes) for parsing
            for line_bytes in stdout_lines_bytes:
                yield line_bytes

            # Check exit code after processing output
            # lsof exits with 1 if some PIDs weren't found or other non-fatal issues
            if return_code != 0 and return_code != 1:
                log.warning(
                    f"lsof command (async) exited with unexpected code: {return_code}"
                )

        except asyncio.TimeoutError:
            # Re-raise timeout if caught from wait_for
            raise TimeoutError("lsof command timed out")
        except Exception as e:
            log.exception(f"Error managing async lsof execution: {e}")
            raise RuntimeError(f"async lsof command failed: {e}") from e

    except FileNotFoundError:
        log.exception("lsof command not found.")
        raise  # Propagate FileNotFoundError
    except (OSError, Exception) as e:
        log.exception(f"Error starting async lsof: {e}")
        # Ensure process is cleaned up if creation failed partially
        if process and process.returncode is None:
            try:
                process.kill()
                await process.wait()
            except ProcessLookupError:
                pass
            except Exception:
                pass  # Ignore errors during cleanup
        raise RuntimeError(f"async lsof command failed: {e}") from e


# --- Snapshot Building ---
async def _lsof_snapshot(pids: list[int]) -> Snapshot:
    """
    Run lsof once for `pids` and build a poll snapshot.

    Numeric file descriptors become OpenFile entries; special entries (cwd, mem,
    txt, DEL, ...) become `stats` paths. Any PID appearing in lsof output is
    present in the snapshot (so the caller knows it is alive); PIDs absent from
    the output are omitted and treated as exited. Raises on lsof failure so the
    caller can skip the cycle rather than mistake it for mass-exit.
    """
    snapshot: Snapshot = {}
    if not pids:
        return snapshot

    trace_enabled = log.isEnabledFor(TRACE_LEVEL_NUM)
    lines: list[bytes] = []
    async for line_bytes in _run_lsof_command_async(pids):
        if trace_enabled:
            log.log(TRACE_LEVEL_NUM, f"Raw lsof line: {line_bytes!r}")
        lines.append(line_bytes)

    for record in _parse_lsof_f_output(iter(lines)):
        pid = record.get("pid")
        if not pid:
            continue
        # Any record with a PID means that PID is alive this cycle.
        files = snapshot.setdefault(pid, PidFiles())

        path_bytes: bytes | None = record.get("path")
        fd = record.get("fd")
        mode: str = record.get("mode", "")

        if fd is None:
            # Special entry (cwd/mem/txt/DEL): report as a stat, not an fd.
            if path_bytes:
                files.stats.append(path_bytes)
        elif fd >= 0 and path_bytes:
            files.fds[fd] = OpenFile(
                fd=fd,
                path=path_bytes,
                read="r" in mode or "u" in mode,
                write="w" in mode or "u" in mode,
                mode=mode,
            )

    return snapshot
