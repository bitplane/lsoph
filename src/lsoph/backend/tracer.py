# Filename: src/lsoph/backend/tracer.py
"""
Shared machinery for backends that run an external tracer subprocess and turn
its line-oriented output into Monitor updates (strace, and future tracers like
fs_usage, truss, dtruss, ...).

This base owns the subprocess lifecycle, output streaming (stdout / stderr / a
private FIFO), stderr logging, task coordination and termination. Subclasses
provide three things: whether the tool is available, the command to run and
where its trace output goes, and how to turn output lines into Monitor updates.
"""

import asyncio
import logging
import os
import shlex
from abc import abstractmethod
from collections.abc import AsyncIterator
from enum import Enum

from lsoph.util.fifo import temp_fifo

from .base import Backend

log = logging.getLogger(__name__)

# Grace period to let the output consumer drain remaining output after the
# tracer process exits, before it is cancelled.
DRAIN_TIMEOUT = 2.0


class OutputChannel(Enum):
    """Where a tracer emits its trace stream."""

    STDOUT = "stdout"
    STDERR = "stderr"
    # The tracer writes to a path we pass it, keeping its trace off the traced
    # program's own stdio. strace uses this (via -o).
    FIFO = "fifo"


class TracerBackend(Backend):
    """Base for backends driven by an external, line-oriented tracer process."""

    # Where this tracer emits its trace stream.
    output_channel: OutputChannel = OutputChannel.STDOUT

    def __init__(self, monitor):
        super().__init__(monitor)
        self._consumer_task: asyncio.Task | None = None
        self._stderr_task: asyncio.Task | None = None

    # --- Subclass contract ---

    @abstractmethod
    def build_command(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ) -> list[str] | None:
        """
        Return the tracer argv. Exactly one of attach_pids / run_command is set.
        output_path is the FIFO path when output_channel is FIFO, else None.
        Return None to abort the launch (e.g. no valid PIDs to attach to).
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    async def process_lines(
        self, lines: AsyncIterator[bytes], attach_ids: list[int] | None
    ) -> None:
        """Consume raw trace lines and update self.monitor until the stream ends."""
        raise NotImplementedError  # pragma: no cover

    def build_env(self, output_path: str | None) -> dict[str, str] | None:
        """Extra environment variables for the tracer subprocess (merged over the
        inherited environment), or None to inherit unchanged. Used e.g. to set
        LD_PRELOAD for the preload backend."""
        return None

    # --- Lifecycle ---

    async def attach(self, pids: list[int]):
        if not pids:
            return
        await self._run(attach_pids=list(pids), run_command=None)

    async def run_command(self, command: list[str]):
        if not command:
            log.error(f"{type(self).__name__}.run_command called with empty command.")
            return
        await self._run(attach_pids=None, run_command=list(command))

    async def _run(self, attach_pids: list[int] | None, run_command: list[str] | None):
        if self.output_channel is OutputChannel.FIFO:
            with temp_fifo(prefix=f"lsoph_{self.backend_name}_") as fifo_path:
                await self._launch(fifo_path, attach_pids, run_command)
        else:
            await self._launch(None, attach_pids, run_command)

    async def _launch(
        self,
        output_path: str | None,
        attach_pids: list[int] | None,
        run_command: list[str] | None,
    ):
        argv = self.build_command(output_path, attach_pids, run_command)
        if not argv:
            log.error(f"{type(self).__name__}: no command to run; aborting.")
            return

        log.info(f"Executing tracer: {' '.join(shlex.quote(a) for a in argv)}")
        extra_env = self.build_env(output_path)
        env = {**os.environ, **extra_env} if extra_env else None
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=(
                    asyncio.subprocess.PIPE
                    if self.output_channel is OutputChannel.STDOUT
                    else asyncio.subprocess.DEVNULL
                ),
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (FileNotFoundError, OSError) as e:
            log.error(f"Failed to launch tracer {type(self).__name__}: {e}")
            return

        self._process = process
        self.monitor.backend_pid = process.pid
        log.info(f"{type(self).__name__} tracer started with PID {process.pid}")

        lines = self._output_lines(process, output_path)
        # When the trace itself arrives on stderr, that stream is the data, so
        # don't also spin up a stderr logger for it.
        if self.output_channel is not OutputChannel.STDERR:
            self._stderr_task = asyncio.create_task(
                self._log_stderr(process.stderr), name=f"{self.backend_name}_stderr"
            )

        self._consumer_task = asyncio.create_task(
            self.process_lines(lines, attach_pids), name=f"{self.backend_name}_consumer"
        )
        process_wait = asyncio.create_task(
            process.wait(), name=f"{self.backend_name}_wait"
        )

        try:
            await asyncio.wait(
                [self._consumer_task, process_wait],
                return_when=asyncio.FIRST_COMPLETED,
            )
            if process_wait.done() and not self._consumer_task.done():
                # Tracer exited: give the consumer a moment to drain buffered
                # output (to EOF) before cancelling it.
                try:
                    await asyncio.wait_for(self._consumer_task, timeout=DRAIN_TIMEOUT)
                except asyncio.TimeoutError:
                    self._consumer_task.cancel()
            if self._consumer_task.done() and not self._consumer_task.cancelled():
                exc = self._consumer_task.exception()
                if exc is not None:
                    log.error(f"{type(self).__name__} consumer failed: {exc!r}")
        except asyncio.CancelledError:
            log.info(f"{type(self).__name__} launch cancelled.")
        finally:
            if not self.should_stop:
                await self.stop()

    async def stop(self):
        """Signal stop, cancel reader tasks, and terminate the tracer process."""
        if self._should_stop.is_set():
            return
        log.info(f"Stopping {type(self).__name__} backend...")
        self._should_stop.set()

        for task in (self._consumer_task, self._stderr_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        self._consumer_task = None
        self._stderr_task = None

        await self._terminate_process()  # SIGTERM -> SIGKILL ladder from Backend.
        log.info(f"{type(self).__name__} backend stopped.")

    # --- Output streaming ---

    def _output_lines(
        self, process: asyncio.subprocess.Process, output_path: str | None
    ) -> AsyncIterator[bytes]:
        if self.output_channel is OutputChannel.FIFO:
            return self._read_fifo(output_path)
        if self.output_channel is OutputChannel.STDOUT:
            return self._read_stream(process.stdout)
        return self._read_stream(process.stderr)

    async def _read_stream(
        self, reader: asyncio.StreamReader | None
    ) -> AsyncIterator[bytes]:
        """Yield newline-stripped lines from a subprocess pipe until EOF/stop."""
        if reader is None:
            return
        while not self.should_stop:
            try:
                line = await reader.readline()
            except (asyncio.IncompleteReadError, asyncio.CancelledError):
                break
            except Exception as e:
                if not self.should_stop:
                    log.exception(f"Error reading tracer output: {e}")
                break
            if not line:
                break  # EOF
            yield line.rstrip(b"\r\n")

    async def _read_fifo(self, fifo_path: str) -> AsyncIterator[bytes]:
        """Yield newline-stripped lines from a FIFO via a StreamReader."""
        log.debug(f"Opening FIFO for reading: {fifo_path}")
        reader = None
        transport = None
        read_fd = -1
        fifo_file_obj = None
        loop = asyncio.get_running_loop()

        try:
            # Opening a FIFO for reading blocks until a writer (the tracer) opens
            # the other end.
            read_fd = os.open(fifo_path, os.O_RDONLY)
            fifo_file_obj = os.fdopen(read_fd, "rb", buffering=0)
            read_fd = -1  # ownership transferred to fifo_file_obj

            reader = asyncio.StreamReader(loop=loop)
            protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
            transport, _ = await loop.connect_read_pipe(lambda: protocol, fifo_file_obj)

            while not self.should_stop:
                try:
                    line = await reader.readline()
                except (asyncio.IncompleteReadError, asyncio.CancelledError):
                    break
                except Exception as e:
                    if not self.should_stop:
                        log.exception(f"Error reading FIFO {fifo_path}: {e}")
                    break
                if not line:
                    break  # EOF
                yield line.rstrip(b"\r\n")

        except FileNotFoundError:
            if not self.should_stop:
                log.error(f"FIFO path not found: {fifo_path}")
        except Exception as e:
            log.exception(f"Failed to open or read FIFO {fifo_path}: {e}")
        finally:
            if transport and not transport.is_closing():
                transport.close()
            if fifo_file_obj:
                try:
                    fifo_file_obj.close()
                except Exception as close_err:
                    log.warning(f"Error closing FIFO file object: {close_err}")
            elif read_fd != -1:
                try:
                    os.close(read_fd)
                except OSError:
                    pass

    async def _log_stderr(self, stderr: asyncio.StreamReader | None):
        """Read the tracer's stderr pipe and log any output at WARNING level."""
        if not stderr:
            return
        try:
            while not self.should_stop:
                try:
                    line = await stderr.readline()
                except (asyncio.IncompleteReadError, asyncio.CancelledError):
                    break
                except Exception as e:
                    if not self.should_stop:
                        log.exception(f"Error reading tracer stderr: {e}")
                    break
                if not line:
                    break
                log.warning(
                    f"{self.backend_name} stderr: "
                    f"{line.decode('utf-8', 'replace').rstrip()}"
                )
        finally:
            log.debug(f"Exiting {self.backend_name} stderr reader.")
