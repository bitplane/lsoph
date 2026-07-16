"""Tests for the file table's I/O column rendering."""

from lsoph.monitor import FileInfo
from lsoph.ui.file_data_table import _format_bytes, _render_io


def test_format_bytes_scales_to_human_units():
    """Byte counts render as human-readable units."""
    assert _format_bytes(512) == "512"
    assert _format_bytes(1024) == "1.0K"
    assert _format_bytes(1536) == "1.5K"
    assert _format_bytes(1048576) == "1.0M"


def test_render_io_shows_read_and_write():
    """A file with reads and writes shows both, arrowed."""
    cell = _render_io(FileInfo(path=b"/x", bytes_read=1234, bytes_written=4096)).plain

    assert "1.2K↓" in cell
    assert "4.0K↑" in cell


def test_render_io_is_blank_without_io():
    """A file with no byte totals (e.g. a poller backend) renders an empty cell."""
    assert _render_io(FileInfo(path=b"/x")).plain == ""
