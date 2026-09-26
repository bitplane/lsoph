# Filename: src/lsoph/ui/log_screen.py
"""Full-screen display for application logs."""

import logging

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import Footer, Header, RichLog

from lsoph.log import LogBuffer

log = logging.getLogger("lsoph.ui.log")


class LogScreen(Screen):
    """A full screen to display application logs using RichLog."""

    BINDINGS = [
        Binding("escape,q,l,ctrl+l", "app.pop_screen", "Close Logs", show=True),
        Binding("c", "clear_log", "Clear", show=True),
        Binding("up,k", "scroll_up()", "Scroll Up", show=False),
        Binding("down,j", "scroll_down()", "Scroll Down", show=False),
        Binding("pageup", "page_up()", "Page Up", show=False),
        Binding("pagedown", "page_down()", "Page Down", show=False),
        Binding("home", "scroll_home()", "Scroll Home", show=False),
        Binding("end", "scroll_end()", "Scroll End", show=False),
    ]

    def __init__(self, log_queue: LogBuffer):
        self.log_queue = log_queue
        self._seen = 0  # log_queue.total at our last read
        self._timer: Timer | None = None
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the log screen."""
        yield Header()
        # Directly yield the RichLog, making it fill the screen body
        yield RichLog(
            id="app-log",
            max_lines=2000,  # Limit stored lines for performance
            auto_scroll=True,  # Keep scrolled to bottom by default
            wrap=False,  # Disable wrapping for log lines
            highlight=True,  # Enable syntax highlighting
            markup=True,  # Enable Rich markup
        )
        yield Footer()

    def on_mount(self) -> None:
        """Called when the screen is mounted. Shows buffered logs and starts timer."""
        self._check_log_queue()
        self.query_one(RichLog).scroll_end(animate=False)
        self._timer = self.set_interval(1 / 10, self._check_log_queue)

    def on_unmount(self) -> None:
        """Called when the screen is unmounted. Stops the timer."""
        if self._timer:
            try:
                self._timer.stop()
                log.debug("LogScreen unmounted. Stopped log queue timer.")
            except Exception as e:
                log.error(f"Error stopping log screen timer: {e}")
        self._timer = None

    def _check_log_queue(self) -> None:
        """Write lines logged since we last looked to the RichLog."""
        lines, self._seen = self.log_queue.since(self._seen)
        log_widget = self.query_one(RichLog)
        for line in lines:
            log_widget.write(line)

    def action_clear_log(self) -> None:
        """Action to clear the log display."""
        try:
            log_widget = self.query_one(RichLog)
            log_widget.clear()
            self.notify("Logs cleared.", timeout=1)
            log.info("Log display cleared by user.")
        except Exception:
            log.exception("Error clearing log display.")
            self.notify("Error clearing log.", severity="error", timeout=3)

    # --- Scrolling Actions ---
    # RichLog handles scrolling internally, but bindings can target its methods
    def action_scroll_up(self) -> None:
        try:
            self.query_one(RichLog).scroll_up(animate=False)
        except Exception:
            pass  # Ignore errors if widget not found

    def action_scroll_down(self) -> None:
        try:
            self.query_one(RichLog).scroll_down(animate=False)
        except Exception:
            pass

    def action_page_up(self) -> None:
        try:
            self.query_one(RichLog).scroll_page_up(animate=False)
        except Exception:
            pass

    def action_page_down(self) -> None:
        try:
            self.query_one(RichLog).scroll_page_down(animate=False)
        except Exception:
            pass

    def action_scroll_home(self) -> None:
        try:
            self.query_one(RichLog).scroll_home(animate=False)
        except Exception:
            pass

    def action_scroll_end(self) -> None:
        try:
            self.query_one(RichLog).scroll_end(animate=False)
        except Exception:
            pass
