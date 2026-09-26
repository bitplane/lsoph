# Filename: src/lsoph/backend/etw/session.py
"""
ctypes layer for a real-time ETW consumer of Microsoft-Windows-Kernel-File.

Four calls do all the work (advapi32): StartTraceW creates a real-time
session, EnableTraceEx2 subscribes the kernel-file provider, OpenTraceW +
ProcessTrace deliver EVENT_RECORDs to a callback (ProcessTrace blocks its
thread until the session is stopped), and ControlTraceW tears it down.

Structure definitions are plain ctypes and import everywhere; anything that
touches ctypes.windll runs only on win32. Struct layouts follow the evntrace/
evntcons headers and have NOT yet been validated on a real Windows host --
under Wine these APIs are stubs, which still smoke-tests the marshalling and
our error paths.
"""

import ctypes
import logging
import threading
from ctypes import (
    POINTER,
    Structure,
    c_int32,
    c_int64,
    c_ubyte,
    c_uint16,
    c_uint32,
    c_uint64,
    c_void_p,
    c_wchar,
    c_wchar_p,
)

from .parse import FileEvent, parse_event

log = logging.getLogger(__name__)

# --- constants (evntrace.h / evntcons.h) ---

WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_CLOCK_SYSTEM_TIME = 2
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_TRACE_CONTROL_STOP = 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
TRACE_LEVEL_INFORMATION = 4
EVENT_HEADER_FLAG_32_BIT_HEADER = 0x0020
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF
ERROR_ALREADY_EXISTS = 183

# FILETIME (100ns ticks since 1601-01-01) -> unix epoch offset.
_FILETIME_EPOCH = 116444736000000000

_MAX_SESSION_NAME = 1024


class GUID(Structure):
    _fields_ = [
        ("Data1", c_uint32),
        ("Data2", c_uint16),
        ("Data3", c_uint16),
        ("Data4", c_ubyte * 8),
    ]


# Microsoft-Windows-Kernel-File: {EDD08927-9CC4-4E65-B970-C2560FB5C289}
KERNEL_FILE_PROVIDER = GUID(
    0xEDD08927,
    0x9CC4,
    0x4E65,
    (c_ubyte * 8)(0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89),
)


class WNODE_HEADER(Structure):
    _fields_ = [
        ("BufferSize", c_uint32),
        ("ProviderId", c_uint32),
        ("HistoricalContext", c_uint64),
        ("TimeStamp", c_int64),
        ("Guid", GUID),
        ("ClientContext", c_uint32),
        ("Flags", c_uint32),
    ]


class EVENT_TRACE_PROPERTIES(Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", c_uint32),
        ("MinimumBuffers", c_uint32),
        ("MaximumBuffers", c_uint32),
        ("MaximumFileSize", c_uint32),
        ("LogFileMode", c_uint32),
        ("FlushTimer", c_uint32),
        ("EnableFlags", c_uint32),
        ("AgeLimit", c_int32),  # LONG, unioned with FlushThreshold
        ("NumberOfBuffers", c_uint32),
        ("FreeBuffers", c_uint32),
        ("EventsLost", c_uint32),
        ("BuffersWritten", c_uint32),
        ("LogBuffersLost", c_uint32),
        ("RealTimeBuffersLost", c_uint32),
        ("LoggerThreadId", c_void_p),
        ("LogFileNameOffset", c_uint32),
        ("LoggerNameOffset", c_uint32),
        # The session name lives in the same allocation, after the struct.
        ("LoggerName", c_wchar * _MAX_SESSION_NAME),
    ]


class EVENT_DESCRIPTOR(Structure):
    _fields_ = [
        ("Id", c_uint16),
        ("Version", c_ubyte),
        ("Channel", c_ubyte),
        ("Level", c_ubyte),
        ("Opcode", c_ubyte),
        ("Task", c_uint16),
        ("Keyword", c_uint64),
    ]


class EVENT_HEADER(Structure):
    _fields_ = [
        ("Size", c_uint16),
        ("HeaderType", c_uint16),
        ("Flags", c_uint16),
        ("EventProperty", c_uint16),
        ("ThreadId", c_uint32),
        ("ProcessId", c_uint32),
        ("TimeStamp", c_int64),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("KernelTime", c_uint32),
        ("UserTime", c_uint32),
        ("ActivityId", GUID),
    ]


class ETW_BUFFER_CONTEXT(Structure):
    _fields_ = [
        ("ProcessorNumber", c_ubyte),
        ("Alignment", c_ubyte),
        ("LoggerId", c_uint16),
    ]


class EVENT_RECORD(Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", c_uint16),
        ("UserDataLength", c_uint16),
        ("ExtendedData", c_void_p),
        ("UserData", c_void_p),
        ("UserContext", c_void_p),
    ]


class EVENT_TRACE_HEADER(Structure):
    _fields_ = [
        ("Size", c_uint16),
        ("FieldTypeFlags", c_uint16),
        ("Version", c_uint32),
        ("ThreadId", c_uint32),
        ("ProcessId", c_uint32),
        ("TimeStamp", c_int64),
        ("Guid", GUID),
        ("KernelTime", c_uint32),
        ("UserTime", c_uint32),
    ]


class EVENT_TRACE(Structure):
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", c_uint32),
        ("ParentInstanceId", c_uint32),
        ("ParentGuid", GUID),
        ("MofData", c_void_p),
        ("MofLength", c_uint32),
        ("ClientContext", c_uint32),
    ]


class SYSTEMTIME(Structure):
    _fields_ = [("_fields", c_uint16 * 8)]


class TIME_ZONE_INFORMATION(Structure):
    _fields_ = [
        ("Bias", c_uint32),
        ("StandardName", c_wchar * 32),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", c_uint32),
        ("DaylightName", c_wchar * 32),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", c_uint32),
    ]


class TRACE_LOGFILE_HEADER(Structure):
    _fields_ = [
        ("BufferSize", c_uint32),
        ("Version", c_uint32),
        ("ProviderVersion", c_uint32),
        ("NumberOfProcessors", c_uint32),
        ("EndTime", c_int64),
        ("TimerResolution", c_uint32),
        ("MaximumFileSize", c_uint32),
        ("LogFileMode", c_uint32),
        ("BuffersWritten", c_uint32),
        ("StartBuffers", c_uint32),
        ("PointerSize", c_uint32),
        ("EventsLost", c_uint32),
        ("CpuSpeedInMHz", c_uint32),
        ("LoggerName", c_wchar_p),
        ("LogFileName", c_wchar_p),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", c_int64),
        ("PerfFreq", c_int64),
        ("StartTime", c_int64),
        ("ReservedFlags", c_uint32),
        ("BuffersLost", c_uint32),
    ]


def _logfile_fields(callback_type) -> list[tuple]:
    """EVENT_TRACE_LOGFILEW fields; the callback type is win32-only."""
    return [
        ("LogFileName", c_wchar_p),
        ("LoggerName", c_wchar_p),
        ("CurrentTime", c_int64),
        ("BuffersRead", c_uint32),
        ("ProcessTraceMode", c_uint32),
        ("CurrentEvent", EVENT_TRACE),
        ("LogfileHeader", TRACE_LOGFILE_HEADER),
        ("BufferCallback", c_void_p),
        ("BufferSize", c_uint32),
        ("Filled", c_uint32),
        ("EventsLost", c_uint32),
        ("EventRecordCallback", callback_type),
        ("IsKernelTrace", c_uint32),
        ("Context", c_void_p),
    ]


def _advapi32():
    """A private advapi32 handle with prototypes declared, so 64-bit handles
    and keyword masks are marshalled as such rather than as C ints."""
    lib = ctypes.WinDLL("advapi32")
    handle, ulong, props = c_uint64, c_uint32, POINTER(EVENT_TRACE_PROPERTIES)
    prototypes = {
        "StartTraceW": (ulong, [POINTER(handle), c_wchar_p, props]),
        "ControlTraceW": (ulong, [handle, c_wchar_p, props, ulong]),
        "EnableTraceEx2": (
            ulong,
            [
                handle,
                POINTER(GUID),
                ulong,
                c_ubyte,
                c_uint64,
                c_uint64,
                ulong,
                c_void_p,
            ],
        ),
        "OpenTraceW": (handle, [c_void_p]),
        "ProcessTrace": (ulong, [POINTER(handle), ulong, c_void_p, c_void_p]),
        "CloseTrace": (ulong, [handle]),
    }
    for name, (restype, argtypes) in prototypes.items():
        func = getattr(lib, name)
        func.restype = restype
        func.argtypes = argtypes
    return lib


def _filetime_to_unix(filetime: int) -> float:
    return (filetime - _FILETIME_EPOCH) / 1e7


class KernelFileSession:
    """Owns one real-time trace session and its blocking consumer loop.

    run() blocks the calling thread inside ProcessTrace, invoking on_event
    with a FileEvent per decoded record; stop() (from any thread) stops the
    session, which unblocks run().
    """

    def __init__(self, name: str, on_event, want_pid=None):
        self.name = name
        self.on_event = on_event
        # Checked against the event header before anything is copied or
        # parsed: the provider is system-wide, and most events are unwanted.
        self.want_pid = want_pid or (lambda pid: True)
        self._session_handle = c_uint64(0)
        self._advapi32 = _advapi32()  # win32 only, by construction
        # Serializes starting the session against stop(): a stop() that lands
        # before StartTraceW must still prevent (or tear down) the session,
        # or ProcessTrace would block forever on a session nobody stops.
        self._lock = threading.Lock()
        self._stopped = False

    def run(self) -> None:
        with self._lock:
            if self._stopped:
                return
            self._start()
        try:
            self._enable_provider()
            self._consume()
        except OSError:
            if not self._stopped:
                raise  # a stop() mid-setup makes the later calls fail; fine
        finally:
            self.stop()

    def _properties(self) -> EVENT_TRACE_PROPERTIES:
        props = EVENT_TRACE_PROPERTIES()
        props.Wnode.BufferSize = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        # EVENT_HEADER.TimeStamp must use the FILETIME-compatible system clock;
        # _filetime_to_unix converts those 100 ns values to Unix timestamps.
        props.Wnode.ClientContext = EVENT_TRACE_CLOCK_SYSTEM_TIME
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.LoggerNameOffset = EVENT_TRACE_PROPERTIES.LoggerName.offset
        return props

    def _start(self) -> None:
        props = self._properties()
        rc = self._advapi32.StartTraceW(
            ctypes.byref(self._session_handle), self.name, ctypes.byref(props)
        )
        if rc == ERROR_ALREADY_EXISTS:
            # A session with our name survived an earlier crash (ETW sessions
            # are system-global and outlive their creator): stop it and retry.
            log.warning(f"Stale ETW session {self.name!r} found; restarting it.")
            self._control_stop()
            props = self._properties()
            rc = self._advapi32.StartTraceW(
                ctypes.byref(self._session_handle), self.name, ctypes.byref(props)
            )
        if rc != 0:
            raise OSError(f"StartTraceW failed with Win32 error {rc}")

    def _enable_provider(self) -> None:
        rc = self._advapi32.EnableTraceEx2(
            self._session_handle,
            ctypes.byref(KERNEL_FILE_PROVIDER),
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            0,  # MatchAnyKeyword: 0 = all events; we filter by ID in dispatch
            0,
            0,
            None,
        )
        if rc != 0:
            raise OSError(f"EnableTraceEx2 failed with Win32 error {rc}")

    def _consume(self) -> None:
        callback_type = ctypes.WINFUNCTYPE(None, POINTER(EVENT_RECORD))

        class EVENT_TRACE_LOGFILEW(Structure):
            _fields_ = _logfile_fields(callback_type)

        # Keep a reference on self: ProcessTrace uses it for the whole loop.
        self._callback = callback_type(self._on_record)
        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.name
        logfile.ProcessTraceMode = (
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        )
        logfile.EventRecordCallback = self._callback

        trace = self._advapi32.OpenTraceW(ctypes.byref(logfile))
        if trace == INVALID_PROCESSTRACE_HANDLE:
            raise OSError("OpenTraceW failed")
        try:
            # Blocks until the session is stopped or the buffers close.
            self._advapi32.ProcessTrace(ctypes.byref(c_uint64(trace)), 1, None, None)
        finally:
            self._advapi32.CloseTrace(c_uint64(trace))

    def _on_record(self, record) -> None:
        header = record.contents.EventHeader
        if header.ProviderId.Data1 != KERNEL_FILE_PROVIDER.Data1:
            return
        if not self.want_pid(header.ProcessId):
            return
        pointer_size = 4 if header.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER else 8
        length = record.contents.UserDataLength
        data = ctypes.string_at(record.contents.UserData, length) if length else b""
        event = parse_event(
            header.EventDescriptor.Id,
            data,
            pointer_size,
            header.ProcessId,
            _filetime_to_unix(header.TimeStamp),
        )
        if event is not None:
            self.on_event(event)

    def _control_stop(self) -> None:
        props = self._properties()
        self._advapi32.ControlTraceW(
            c_uint64(0), self.name, ctypes.byref(props), EVENT_TRACE_CONTROL_STOP
        )

    def stop(self) -> None:
        """Stop the session; safe to call from any thread, repeatedly, and
        before run() has started it."""
        with self._lock:
            self._stopped = True
            self._control_stop()


def is_admin() -> bool:
    """True when running elevated (kernel providers need it). win32 only."""
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def dos_device_map() -> dict[bytes, bytes]:
    """Map NT device prefixes to drive letters (\\Device\\HarddiskVolume2 ->
    C:), for translating kernel-file paths. win32 only."""
    kernel32 = ctypes.windll.kernel32
    mapping: dict[bytes, bytes] = {}
    target = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:"
        if kernel32.QueryDosDeviceW(drive, target, 1024):
            mapping[target.value.encode("utf-8")] = drive.encode("utf-8")
    return mapping


__all__ = ["KernelFileSession", "is_admin", "dos_device_map", "FileEvent"]
