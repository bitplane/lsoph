# Filename: src/lsoph/backend/base.py
"""Base definitions for asynchronous monitoring backends."""

import asyncio
import logging
import os
import signal
from abc import ABC, abstractmethod

from lsoph.monitor import Monitor

log = logging.getLogger("lsoph.backend.base")


class Backend(ABC):
    """Abstract Base Class for all monitoring backends."""

    # Class attribute intended to be overridden by subclasses
    # This name is used as the key in the BACKENDS dictionary
    backend_name: str = "base"

    def __init__(self, monitor: Monitor):
        """Initialize the backend."""
        self.monitor = monitor
        self._should_stop = asyncio.Event()
        self._process: asyncio.subprocess.Process | None = None
        log.info(f"Initializing backend: {self.__class__.__name__}")

    @staticmethod
    @abstractmethod
    def is_available() -> bool:
        """
        Check if the backend's dependencies (e.g., executable) are met.
        This MUST be implemented by subclasses.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    async def attach(self, pids: list[int]):
        """
        Asynchronously attach to and monitor existing process IDs.
        Should periodically check `self.should_stop`.
        """
        pass  # pragma: no cover

    async def run_command(self, command: list[str]):
        """
        Default implementation to run a command and monitor it using the backend's attach method.
        Backends like strace should override this if they have a different run mechanism.
        """
        if not command:
            log.error(
                f"{self.__class__.__name__}.run_command called with empty command."
            )
            return

        log.info(f"{self.__class__.__name__}: Running command: {' '.join(command)}")
        process: asyncio.subprocess.Process | None = None
        attach_task: asyncio.Task | None = None

        try:
            # Start the process in its own session so stop() can signal the whole
            # tree (the command plus anything it spawns).
            process = await self._spawn(
                command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            if process is None:
                await self.stop()
                return
            pid = process.pid
            log.info(f"Command '{' '.join(command)}' started with PID: {pid}")

            # Create a task to run the attach method for the new PID.
            # Backends implementing attach should handle descendant tracking if appropriate.
            attach_task = asyncio.create_task(
                self.attach([pid]), name=f"attach_task_{pid}"
            )

            # Wait for either the attach task to complete (e.g., cancellation)
            # or the monitored process to exit, or the stop event.
            process_wait_task = asyncio.create_task(
                process.wait(), name=f"process_wait_{pid}"
            )
            stop_wait_task = asyncio.create_task(
                self._should_stop.wait(), name=f"stop_wait_{pid}"
            )

            done, pending = await asyncio.wait(
                [attach_task, process_wait_task, stop_wait_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Handle results/cancellation
            if process_wait_task in done:
                return_code = process.returncode
                log.info(
                    f"Command process {pid} exited with code {return_code}. Stopping attach task."
                )
                # Process finished, signal attach task to stop (if not already done)
                await self.stop()
                if attach_task not in done:  # If attach task is still pending
                    attach_task.cancel()
            elif stop_wait_task in done:
                log.info(
                    f"Stop signal received for command '{' '.join(command)}'. Terminating process and attach task."
                )
                # Stop was called externally, cancel attach and terminate process
                if attach_task not in done:
                    attach_task.cancel()
                if process_wait_task not in done:
                    await self._terminate_process()
            elif attach_task in done:
                log.info(
                    f"Attach task for command '{' '.join(command)}' finished unexpectedly or was cancelled."
                )
                # Attach finished (maybe cancelled), ensure process is stopped
                if process_wait_task not in done:
                    await self._terminate_process()

            # Cancel any remaining pending tasks
            for task in pending:
                if not task.done():
                    task.cancel()
                    try:
                        await task  # Allow cancellation to propagate
                    except asyncio.CancelledError:
                        pass  # Expected

        except FileNotFoundError:
            log.exception(f"Command not found: {command[0]}")
            await self.stop()  # Ensure stop is signalled
        except (OSError, Exception) as e:
            log.exception(
                f"Failed to start or manage command '{' '.join(command)}': {e}"
            )
            await self.stop()  # Ensure stop is signalled
            # Ensure process is terminated if it started
            if process and process.returncode is None:
                await self._terminate_process()
            # Ensure attach task is cancelled if it started
            if attach_task and not attach_task.done():
                attach_task.cancel()
                try:
                    await attach_task
                except asyncio.CancelledError:
                    pass  # Expected
        finally:
            log.info(f"Finished run_command for: {' '.join(command)}")
            self._process = None

    async def _spawn(
        self,
        argv: list[str],
        *,
        stdout: int,
        stderr: int,
        env: dict[str, str] | None = None,
    ) -> asyncio.subprocess.Process | None:
        """Launch a monitored subprocess in its own session, storing it as
        self._process. start_new_session makes the child a process-group leader
        (pgid == pid) so _terminate can signal its whole tree at once. Returns
        None (logged) if the executable can't be launched.

        This is the single spawn point for backend-managed processes -- both the
        run-mode command (PollingBackend) and external tracers (TracerBackend)
        go through it, so their lifecycle handling cannot diverge.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=stdout,
                stderr=stderr,
                env=env,
                start_new_session=True,
            )
        except (FileNotFoundError, OSError) as e:
            log.error(f"Failed to launch {argv[0]}: {e}")
            return None
        self._process = process
        self.monitor.backend_pid = process.pid
        return process

    async def _terminate_process(self):
        """Terminate the managed subprocess and the whole process tree it leads."""
        process, self._process = self._process, None
        await self._terminate(process)

    async def _terminate(self, process: asyncio.subprocess.Process | None):
        """Tear down a subprocess and every process in its group.

        Subprocesses are spawned via _spawn (start_new_session=True), so each is
        a process-group leader; signalling the group tears down children too.
        Killing only the leader would orphan wrappers' children (strace's tracee,
        watch's cat, ...) -- and because they inherit the leader's pipes, that
        also stops asyncio's wait() from returning until they exit on their own.
        """
        if not process or process.returncode is not None:
            return
        if not await self._signal_group(process, signal.SIGTERM, timeout=1.0):
            log.warning(
                f"Process group {process.pid} ignored SIGTERM; sending SIGKILL."
            )
            await self._signal_group(process, signal.SIGKILL, timeout=None)

    async def _signal_group(
        self,
        process: asyncio.subprocess.Process,
        sig: int,
        timeout: float | None,
    ) -> bool:
        """Signal the process's group, then wait for it to exit. Returns True if
        it exited (or was already gone), False on timeout. process.pid is the
        pgid, guaranteed by _spawn's start_new_session=True."""
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return True  # group already gone
        try:
            if timeout is None:
                await process.wait()
            else:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def stop(self):
        """Signals the backend's running task to stop and terminates the managed process if any."""
        if not self._should_stop.is_set():
            log.info(f"Signalling backend {self.__class__.__name__} to stop.")
            self._should_stop.set()
            # Also terminate the process if run_command started one
            await self._terminate_process()
        else:
            log.debug(f"Backend {self.__class__.__name__} stop already signalled.")

    @property
    def should_stop(self) -> bool:
        """Check if the stop event has been set."""
        return self._should_stop.is_set()
