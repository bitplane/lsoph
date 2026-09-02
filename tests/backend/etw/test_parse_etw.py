"""Tests for the kernel-file ETW payload parser.

Buffers are built to the manifest-documented layouts (fields in order,
pointers little-endian, strings null-terminated UTF-16LE), so these verify
the parsing logic; real-Windows capture validation is still pending.
"""

import struct

from lsoph.backend.etw.parse import (
    CLOSE,
    CREATE,
    DELETE_PATH,
    READ,
    parse_event,
)
from lsoph.backend.etw.session import (
    EVENT_TRACE_CLOCK_SYSTEM_TIME,
    KernelFileSession,
)


def test_session_requests_filetime_compatible_timestamps():
    """The session clock must match the FILETIME conversion used by callbacks."""
    session = object.__new__(KernelFileSession)

    props = session._properties()

    assert props.Wnode.ClientContext == EVENT_TRACE_CLOCK_SYSTEM_TIME


def _wstr(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def test_create_extracts_file_object_and_name():
    """Create (12): FileObject after Irp, FileName after four ULONGs."""
    data = struct.pack("<QQIIII", 0x1111, 0xBEEF, 4, 0, 0, 7) + _wstr(r"C:\a.txt")

    event = parse_event(CREATE, data, pointer_size=8, pid=100, timestamp=1.0)

    assert event.file_object == 0xBEEF
    assert event.path == rb"C:\a.txt"


def test_create_with_32_bit_pointers():
    """The same event from a 32-bit process has 4-byte pointers."""
    data = struct.pack("<IIIIII", 0x1111, 0xBEEF, 4, 0, 0, 7) + _wstr(r"C:\a.txt")

    event = parse_event(CREATE, data, pointer_size=4, pid=100, timestamp=1.0)

    assert event.file_object == 0xBEEF
    assert event.path == rb"C:\a.txt"


def test_read_extracts_io_size():
    """Read (15): IOSize follows ByteOffset, three pointers and the tid."""
    data = struct.pack("<QQQQIII", 0, 0x1, 0xBEEF, 0x2, 4, 4096, 0)

    event = parse_event(READ, data, pointer_size=8, pid=100, timestamp=1.0)

    assert event.file_object == 0xBEEF
    assert event.size == 4096


def test_close_extracts_file_object():
    """Close (14): FileObject is the second pointer."""
    data = struct.pack("<QQQI", 0x1, 0xBEEF, 0x2, 4)

    event = parse_event(CLOSE, data, pointer_size=8, pid=100, timestamp=1.0)

    assert event.file_object == 0xBEEF


def test_delete_path_extracts_the_path():
    """DeletePath (26): FilePath after four pointers and two ULONGs."""
    data = struct.pack("<QQQQII", 0x1, 0xBEEF, 0x2, 0, 4, 0) + _wstr(r"C:\gone")

    event = parse_event(DELETE_PATH, data, pointer_size=8, pid=100, timestamp=1.0)

    assert event.path == rb"C:\gone"


def test_unhandled_event_id_returns_none():
    """Event IDs we don't decode (e.g. QueryInformation) are ignored."""
    assert parse_event(22, b"\x00" * 32, pointer_size=8, pid=100, timestamp=1.0) is None
