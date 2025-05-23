# Filename: src/lsoph/ui/detail_screen.py
"""Screen to display file event history using a DataTable. Handles bytes path."""

import datetime
import logging
import os  # For os.fsdecode
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static

from lsoph.monitor import FileInfo  # FileInfo.path is bytes

# short_path accepts bytes, returns str
from lsoph.util.short_path import short_path

# Import the emoji map from the emoji module
from .emoji import DEFAULT_EMOJI, EVENT_EMOJI_MAP, STATUS_EMOJI_MAP

log = logging.getLogger("lsoph.ui.detail")


class DetailScreen(Screen):
    """Screen to display event history and details for a specific file using DataTable."""

    BINDINGS = [
        Binding("escape,q,d,enter", "app.pop_screen", "Close", show=True),
    ]

    def __init__(self, file_info: FileInfo):  # Receives FileInfo with bytes path
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the detail screen."""
        with Vertical(id="detail-content"):
            yield Static(self._create_header_text(), id="detail-header")
            yield DataTable(id="event-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def _create_header_text(self) -> Text:
        """Creates the header text displayed above the table (decodes path)."""
        # --- DECODE AND SHORTEN PATH ---
        # Use short_path utility which accepts bytes and returns decoded, shortened string
        path_display_str = short_path(self.file_info.path, 100)
        # -----------------------------
        status = self.file_info.status.upper()
        style = ""
        if self.file_info.status == "error":
            style = "bold red"
        elif self.file_info.is_open:
            style = "bold green"
        elif self.file_info.status == "deleted":
            style = "strike"

        header = Text.assemble(
            "Details for: ", (path_display_str, "bold"), " | Status: ", (status, style)
        )
        return header

    def on_mount(self) -> None:
        """Called when the screen is mounted. Populates the DataTable."""
        try:
            table = self.query_one(DataTable)
            # Update the static header widget
            self.query_one("#detail-header", Static).update(self._create_header_text())

            # Add columns to the DataTable
            table.add_column("Timestamp", key="ts", width=12)
            table.add_column(
                "Event", key="event", width=12
            )  # Adjusted width slightly for emoji
            table.add_column("Result", key="result", width=6)
            # Let Details column be flexible - NO width specified
            table.add_column("Details", key="details")

            history = self.file_info.event_history
            log.debug(
                f"DetailScreen on_mount: Populating table with {len(history)} history events for {os.fsdecode(self.file_info.path)!r}."
            )

            if not history:
                table.add_row(
                    Text("No event history recorded for this file.", style="dim")
                )
                return

            # Write each event from history as a row
            for event in history:
                # Format timestamp
                ts_raw = event.get("ts", 0)
                ts_str = f"{ts_raw:.3f}"
                try:
                    if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                        ts_str = datetime.datetime.fromtimestamp(ts_raw).strftime(
                            "%H:%M:%S.%f"
                        )[:-3]
                except (TypeError, ValueError, OSError) as ts_err:
                    log.warning(f"Could not format timestamp {ts_raw}: {ts_err}")
                ts_text = Text(ts_str)

                # Get Event Type and Success
                event_type_str = str(event.get("type", "?")).upper()
                success = event.get("success", True)  # Default to True if missing

                # Determine Emoji
                emoji = DEFAULT_EMOJI
                if not success:
                    emoji = EVENT_EMOJI_MAP.get("ERROR", DEFAULT_EMOJI)
                else:
                    emoji = EVENT_EMOJI_MAP.get(event_type_str, DEFAULT_EMOJI)

                # Create Event Text with Emoji Prefix
                etype_text = Text(f"{emoji} {event_type_str}")

                # Format result (OK/FAIL)
                result_text = (
                    Text("OK", style="green") if success else Text("FAIL", style="red")
                )

                # Format details dictionary
                details_dict: dict[str, Any] = event.get("details", {})
                # Filter details, decode bytes paths if present for display
                filtered_details = {}
                for k, v in details_dict.items():
                    if k not in [
                        "syscall",
                        "type",
                        "success",
                        "ts",
                        "error_msg",
                        # Exclude raw path details if they are bytes, handle below
                        "target_path",
                        "source_path",
                        "renamed_to",
                        "renamed_from",
                    ]:
                        # Decode other potential bytes values for display
                        if isinstance(v, bytes):
                            filtered_details[k] = os.fsdecode(v, "surrogateescape")
                        else:
                            filtered_details[k] = v

                # Handle specific path details, decoding them
                for path_key in [
                    "target_path",
                    "source_path",
                    "renamed_to",
                    "renamed_from",
                ]:
                    if path_key in details_dict and isinstance(
                        details_dict[path_key], bytes
                    ):
                        # Add decoded path string to filtered details
                        filtered_details[path_key] = os.fsdecode(
                            details_dict[path_key], "surrogateescape"
                        )

                error_name = details_dict.get("error_name")
                if error_name and not success:
                    filtered_details["ERROR"] = Text(error_name, style="red")

                details_parts = []
                for k, v in filtered_details.items():
                    if isinstance(v, Text):
                        # Use plain representation for consistent formatting
                        details_parts.append(f"{k}={v.plain!r}")
                    else:
                        details_parts.append(f"{k}={v!r}")

                details_str = ", ".join(details_parts)
                # Use a reasonable max width for shortening details text
                details_display = short_path(
                    details_str.encode("utf-8", "surrogateescape"), 100
                )  # Encode back for short_path
                details_text = Text(details_display)

                # Add the row to the table
                table.add_row(ts_text, etype_text, result_text, details_text)

            # Focus the table after populating
            table.focus()

        except Exception as e:
            log.exception(
                f"Error populating detail screen table for {os.fsdecode(self.file_info.path)!r}"
            )
            try:
                table = self.query_one(DataTable)
                table.clear()
                table.add_row(Text(f"Error loading details: {e}", style="bold red"))
            except Exception:
                pass
            self.notify("Error loading details.", severity="error")
