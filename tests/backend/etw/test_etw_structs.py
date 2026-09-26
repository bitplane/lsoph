"""ctypes layouts must match the Windows SDK, field for field.

Offsets (not total sizes) are compared, because c_wchar is 4 bytes on Linux
and 2 on Windows, which changes the size of the trailing name buffers."""

import ctypes

import pytest

from lsoph.backend.etw import session

pytestmark = pytest.mark.skipif(
    ctypes.sizeof(ctypes.c_void_p) != 8, reason="SDK offsets below are for x64"
)


def test_event_trace_properties_offsets_match_the_sdk():
    props = session.EVENT_TRACE_PROPERTIES
    assert ctypes.sizeof(session.WNODE_HEADER) == 48
    assert props.AgeLimit.offset == 76
    assert props.NumberOfBuffers.offset == 80
    assert props.LoggerThreadId.offset == 104
    assert props.LogFileNameOffset.offset == 112
    assert props.LoggerNameOffset.offset == 116
    # The session name follows the fixed 120-byte struct.
    assert props.LoggerName.offset == 120
