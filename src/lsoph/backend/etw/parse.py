# Filename: src/lsoph/backend/etw/parse.py
"""
Parsers for Microsoft-Windows-Kernel-File ETW event payloads.

Layouts follow the provider manifest (event version 1, as shipped since
Windows 10): fixed-width fields in declaration order, pointers sized by the
traced process bitness, strings as null-terminated UTF-16LE. Field order is
unit-tested against synthetic buffers built to the documented layout, but has
NOT yet been validated against captures from a real Windows host.

The payload does not include the PID or timestamp -- those live in the ETW
event header and are passed in by the session layer.
"""

import struct
from dataclasses import dataclass

# Event IDs from the Microsoft-Windows-Kernel-File manifest.
CREATE = 12
CLOSE = 14
READ = 15
WRITE = 16
DELETE_PATH = 26
RENAME_PATH = 27
CREATE_NEW_FILE = 30


@dataclass(frozen=True)
class FileEvent:
    """One decoded kernel-file event, normalized for dispatch."""

    event_id: int
    pid: int
    timestamp: float
    # Kernel FILE_OBJECT pointer: the stable identity of an open file between
    # its Create and Close events -- used the way fds are used elsewhere.
    file_object: int
    path: bytes | None = None  # UTF-8; NT form (\Device\...) until translated
    size: int = 0  # bytes transferred (READ/WRITE only)


def _wstring(data: bytes, offset: int) -> bytes:
    """Extract a null-terminated UTF-16LE string as UTF-8 bytes."""
    end = offset
    while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
        end += 2
    return (
        data[offset:end]
        .decode("utf-16-le", "surrogatepass")
        .encode("utf-8", "surrogatepass")
    )


def _pointer(data: bytes, offset: int, size: int) -> int:
    return int.from_bytes(data[offset : offset + size], "little")


def parse_event(
    event_id: int, data: bytes, pointer_size: int, pid: int, timestamp: float
) -> FileEvent | None:
    """Decode one event payload, or None for event IDs we don't handle."""
    p = pointer_size

    if event_id in (CREATE, CREATE_NEW_FILE):
        # Irp(p) FileObject(p) IssuingThreadId(4) CreateOptions(4)
        # CreateAttributes(4) ShareAccess(4) FileName(wstr)
        file_object = _pointer(data, p, p)
        path = _wstring(data, 2 * p + 16)
        return FileEvent(event_id, pid, timestamp, file_object, path=path)

    if event_id in (READ, WRITE):
        # ByteOffset(8) Irp(p) FileObject(p) FileKey(p) IssuingThreadId(4)
        # IOSize(4) IOFlags(4) [ExtraFlags(4) in v1]
        file_object = _pointer(data, 8 + p, p)
        (size,) = struct.unpack_from("<I", data, 8 + 3 * p + 4)
        return FileEvent(event_id, pid, timestamp, file_object, size=size)

    if event_id == CLOSE:
        # Irp(p) FileObject(p) FileKey(p) IssuingThreadId(4)
        file_object = _pointer(data, p, p)
        return FileEvent(event_id, pid, timestamp, file_object)

    if event_id in (DELETE_PATH, RENAME_PATH):
        # Irp(p) FileObject(p) FileKey(p) ExtraInformation(p)
        # IssuingThreadId(4) InfoClass(4) FilePath(wstr)
        file_object = _pointer(data, p, p)
        path = _wstring(data, 4 * p + 8)
        return FileEvent(event_id, pid, timestamp, file_object, path=path)

    return None
