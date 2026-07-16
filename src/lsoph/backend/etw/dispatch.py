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

    try:
        if event.event_id == READ:
            monitor.read(pid, fobj, None, True, ts, bytes=event.size, **details)
        elif event.event_id == WRITE:
            monitor.write(pid, fobj, None, True, ts, bytes=event.size, **details)
        elif event.event_id == CLOSE:
            monitor.close(pid, fobj, True, ts, **details)
        elif event.event_id == RENAME_PATH:
            # FilePath is the new name; the old one is whatever the FILE_OBJECT
            # was opened as. Without that mapping, record the new path as
            # accessed rather than guessing a rename pair.
            old = monitor.get_path(pid, fobj)
            monitor.rename(pid, old, event.path, True, ts, **details)
        elif event.event_id == DELETE_PATH:
            monitor.delete(pid, event.path, True, ts, **details)
    except KeyError:
        if event.event_id == RENAME_PATH:
            monitor.stat(pid, event.path, True, ts, **details)
        else:
            log.debug(f"PID {pid}: unknown FILE_OBJECT {fobj:#x}, event skipped")
