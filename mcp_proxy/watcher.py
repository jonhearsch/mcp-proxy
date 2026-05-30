"""File system watcher for live configuration reloading."""

import logging
import threading
from pathlib import Path

from watchdog.events import FileSystemEventHandler


class ConfigFileHandler(FileSystemEventHandler):
    """
    File system event handler for monitoring MCP configuration file changes.

    This handler watches for changes to the configuration file and triggers
    a server reload when modifications are detected. It includes debouncing
    to handle editors that save files multiple times in quick succession.

    Features:
    - Debounced reload to prevent multiple rapid reloads
    - Handles file modification, creation, moves, and deletion
    - Works with editors that use atomic saves (temp file + rename)
    """

    def __init__(self, config_path: str, reload_callback, logger: logging.Logger = None):
        """
        Initialize the config file handler.

        Args:
            config_path: Path to the configuration file to monitor
            reload_callback: Function to call when reload should be triggered
            logger: Logger instance for output (defaults to module logger)
        """
        self.config_path = Path(config_path).resolve()
        self.reload_callback = reload_callback
        self.debounce_timer = None
        self.debounce_delay = 1.0  # Wait 1 second after last change to avoid rapid reloads
        self.logger = logger or logging.getLogger(__name__)

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        if Path(event.src_path).resolve() == self.config_path:
            self._debounced_reload()

    def on_moved(self, event):
        """
        Handle file move/rename events.

        Many editors save files atomically by writing to a temp file
        and then renaming it to the target file.
        """
        if event.is_directory:
            return

        if Path(event.dest_path).resolve() == self.config_path:
            self._debounced_reload()

    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return

        if Path(event.src_path).resolve() == self.config_path:
            self.logger.info(f"Config file {self.config_path} was recreated")
            self._debounced_reload()

    def on_deleted(self, event):
        """Handle file deletion events."""
        if event.is_directory:
            return

        if Path(event.src_path).resolve() == self.config_path:
            self.logger.warning(f"Config file {self.config_path} was deleted")
            # Don't trigger reload on deletion - wait for recreation

    def _debounced_reload(self):
        """
        Implement debouncing to prevent multiple rapid reloads.

        Some editors and file operations can trigger multiple filesystem
        events in quick succession. This method ensures we only reload
        once after the events have settled.
        """
        if self.debounce_timer:
            self.debounce_timer.cancel()

        self.debounce_timer = threading.Timer(self.debounce_delay, self._trigger_reload)
        self.debounce_timer.start()

    def _trigger_reload(self):
        """Execute the actual reload callback."""
        self.logger.info(f"Config file {self.config_path} changed, triggering reload...")
        self.reload_callback()
