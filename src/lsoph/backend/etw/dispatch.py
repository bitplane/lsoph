# Filename: src/lsoph/backend/etw/dispatch.py
"""Dispatch decoded kernel-file events into the Monitor.

The FILE_OBJECT pointer plays the role an fd plays for the syscall tracers:
Create maps it to a path, Read/Write/Close resolve through that mapping, and
an unknown FILE_OBJECT (opened before the trace session started) is skipped
quietly, mirroring the strace handlers' unknown-fd guard.
"""

import logging

from lsoph.monitor import Monitor

from .parse import (
    CLOSE,
    CREATE,
    CREATE_NEW_FILE,
    DELETE_PATH,
    READ,
    RENAME_PATH,
    WRITE,
    FileEvent,
)

log = logging.getLogger(__name__)


def process_file_event(
    event: FileEvent, monitor: Monitor, watched_pids: set[int]
) -> None:
    """Apply one event to the monitor, filtered to the watched PID set."""
    if event.pid not in watched_pids:
        return
    pid, ts, fobj = event.pid, event.timestamp, event.file_object
    details = {"source": "etw"}

    if event.event_id in (CREATE, CREATE_NEW_FILE):
        monitor.open(pid, event.path, fobj, True, ts, **details)
        return

    if event.event_id == DELETE_PATH:
        monitor.delete(pid, event.path, True, ts, **details)
        return

    # Everything else resolves through the FILE_OBJECT. One we never saw
    # created (opened before the session started) is skipped here, rather
    # than letting Monitor.get_path fall back to a psutil handle scan on the
    # event loop -- which can't match a FILE_OBJECT anyway.
    if fobj not in monitor.pid_fd_map.get(pid, {}):
        if event.event_id == RENAME_PATH:
            # No old name to pair with: record the new path as accessed.
            monitor.stat(pid, event.path, True, ts, **details)
        else:
            log.debug(f"PID {pid}: unknown FILE_OBJECT {fobj:#x}, event skipped")
        return

    if event.event_id == READ:
        monitor.read(pid, fobj, None, True, ts, bytes=event.size, **details)
    elif event.event_id == WRITE:
        monitor.write(pid, fobj, None, True, ts, bytes=event.size, **details)
    elif event.event_id == CLOSE:
        monitor.close(pid, fobj, True, ts, **details)
    elif event.event_id == RENAME_PATH:
        # FilePath is the new name; the old one is what the FILE_OBJECT was
        # opened as.
        monitor.rename(
            pid, monitor.get_path(pid, fobj), event.path, True, ts, **details
        )
