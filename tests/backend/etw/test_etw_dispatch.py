"""Tests for ETW event dispatch into a real Monitor.

The FILE_OBJECT pointer serves as the fd: Create maps it, Read/Write/Close
resolve through it, unknown FILE_OBJECTs are skipped quietly.
"""

from lsoph.backend.etw.dispatch import process_file_event
from lsoph.backend.etw.parse import (
    CLOSE,
    CREATE,
    DELETE_PATH,
    READ,
    RENAME_PATH,
    WRITE,
    FileEvent,
)
from lsoph.monitor import Monitor

FOBJ = 0xFFFFAB00DEADBEEF


def test_create_then_read_records_bytes_against_the_path():
    """Read resolves the FILE_OBJECT mapped by the earlier Create."""
    monitor = Monitor(identifier="t")
    process_file_event(
        FileEvent(CREATE, 100, 1.0, FOBJ, path=rb"C:\a.txt"), monitor, {100}
    )

    process_file_event(FileEvent(READ, 100, 2.0, FOBJ, size=512), monitor, {100})

    assert monitor.files[rb"C:\a.txt"].bytes_read == 512


def test_write_then_close_marks_the_file_closed():
    """Write and Close both resolve via the FILE_OBJECT mapping."""
    monitor = Monitor(identifier="t")
    process_file_event(
        FileEvent(CREATE, 100, 1.0, FOBJ, path=rb"C:\a.txt"), monitor, {100}
    )

    process_file_event(FileEvent(WRITE, 100, 2.0, FOBJ, size=64), monitor, {100})
    process_file_event(FileEvent(CLOSE, 100, 3.0, FOBJ), monitor, {100})

    info = monitor.files[rb"C:\a.txt"]
    assert info.bytes_written == 64
    assert info.status == "closed"


def test_delete_path_marks_deleted():
    """DeletePath carries the path directly; no mapping needed."""
    monitor = Monitor(identifier="t")
    process_file_event(
        FileEvent(CREATE, 100, 1.0, FOBJ, path=rb"C:\gone"), monitor, {100}
    )

    process_file_event(
        FileEvent(DELETE_PATH, 100, 2.0, FOBJ, path=rb"C:\gone"), monitor, {100}
    )

    assert monitor.files[rb"C:\gone"].status == "deleted"


def test_rename_moves_state_to_the_new_path():
    """RenamePath pairs the mapped old path with the event's new path."""
    monitor = Monitor(identifier="t")
    process_file_event(
        FileEvent(CREATE, 100, 1.0, FOBJ, path=rb"C:\old"), monitor, {100}
    )

    process_file_event(
        FileEvent(RENAME_PATH, 100, 2.0, FOBJ, path=rb"C:\new"), monitor, {100}
    )

    assert rb"C:\new" in monitor.files
    assert rb"C:\old" not in monitor.files


def test_unknown_file_object_is_skipped_without_raising():
    """A Read on a FILE_OBJECT opened before the session started is dropped."""
    monitor = Monitor(identifier="t")

    process_file_event(FileEvent(READ, 100, 1.0, FOBJ, size=512), monitor, {100})

    assert len(monitor) == 0


def test_unwatched_pid_is_filtered_out():
    """The provider is system-wide; events from other PIDs never dispatch."""
    monitor = Monitor(identifier="t")

    process_file_event(
        FileEvent(CREATE, 999, 1.0, FOBJ, path=rb"C:\other"), monitor, {100}
    )

    assert len(monitor) == 0
