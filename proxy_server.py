"""
MCP Proxy Server - A resilient proxy server for Model Context Protocol (MCP) servers.

This module provides a robust proxy server that can manage multiple MCP servers
through a single FastMCP endpoint. It includes features like:

- Automatic restart on crashes
- Live configuration reloading
- Graceful shutdown handling
- File system monitoring for config changes
- Retry logic with exponential backoff
- Port availability checking

Environment Variables:
    MCP_CONFIG_PATH: Path to configuration file (default: mcp_config.json)
    MCP_MAX_RETRIES: Maximum config load retries (default: 3)
    MCP_RESTART_DELAY: Initial restart delay in seconds (default: 5)
    MCP_LIVE_RELOAD: Enable live config reloading (default: false)
"""

# Core libraries
from fastmcp import FastMCP
import os
import sys
import json
import signal
import time
import logging
import threading
import socket
from pathlib import Path
from typing import Optional

# File watching for live reload
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Version information
try:
    from version import get_version, get_version_info
except ImportError:
    # Fallback if version.py is not available
    def get_version():
        return "unknown"
    def get_version_info():
        return {"full": "unknown"}

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

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

    def __init__(self, config_path: str, reload_callback):
        """
        Initialize the config file handler.

        Args:
            config_path: Path to the configuration file to monitor
            reload_callback: Function to call when reload should be triggered
        """
        self.config_path = Path(config_path).resolve()
        self.reload_callback = reload_callback
        self.debounce_timer = None
        self.debounce_delay = 1.0  # Wait 1 second after last change to avoid rapid reloads

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        # Check if the modified file is our config file
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

        # Handle file renames/moves that affect our config
        if Path(event.dest_path).resolve() == self.config_path:
            self._debounced_reload()

    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return

        # Handle config file recreation (after deletion)
        if Path(event.src_path).resolve() == self.config_path:
            logger.info(f"Config file {self.config_path} was recreated")
            self._debounced_reload()

    def on_deleted(self, event):
        """Handle file deletion events."""
        if event.is_directory:
            return

        # Handle config file deletion
        if Path(event.src_path).resolve() == self.config_path:
            logger.warning(f"Config file {self.config_path} was deleted")
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
        logger.info(f"Config file {self.config_path} changed, triggering reload...")
        self.reload_callback()

class ResilientMCPProxy:
    """
    A resilient MCP proxy server with automatic restart and live reload capabilities.

    This class manages the lifecycle of a FastMCP proxy server, providing:
    - Automatic restart on crashes with exponential backoff
    - Live configuration reloading via file system monitoring
    - Graceful shutdown handling with signal management
    - Retry logic for configuration loading
    - Port availability checking before restart

    The proxy creates a single FastMCP instance that can proxy multiple
    MCP servers as defined in the configuration file.
    """

    def __init__(self, config_path: str, max_retries: int = 3, restart_delay: int = 5, enable_live_reload: bool = True):
        """
        Initialize the resilient MCP proxy.

        Args:
            config_path: Path to the JSON configuration file
            max_retries: Maximum number of retries for config loading
            restart_delay: Initial delay between restarts (seconds)
            enable_live_reload: Whether to enable live config reloading
        """
        # Configuration settings
        self.config_path = config_path
        self.max_retries = max_retries
        self.restart_delay = restart_delay
        self.enable_live_reload = enable_live_reload

        # Runtime state
        self.proxy: Optional[FastMCP] = None
        self.shutdown_requested = False
        self.reload_requested = False
        self.config = None

        # File watching components
        self.file_observer: Optional[Observer] = None
        self.config_handler: Optional[ConfigFileHandler] = None

    def wait_for_port_available(self, host: str = "0.0.0.0", port: int = 8080, timeout: int = 10):
        """
        Wait for a network port to become available.

        This is crucial for live reloading since the previous server process
        may take time to release the port after termination.

        Args:
            host: Host address to check
            port: Port number to check
            timeout: Maximum time to wait in seconds

        Returns:
            bool: True if port becomes available, False on timeout
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Attempt to bind to the port to test availability
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((host, port))
                    logger.info(f"✓ Port {port} is available")
                    return True
            except OSError:
                # Port still in use, wait a bit more
                logger.info(f"Port {port} still in use, waiting...")
                time.sleep(0.5)

        logger.warning(f"Port {port} did not become available within {timeout} seconds")
        return False

    def setup_signal_handlers(self):
        """
        Configure signal handlers for graceful shutdown.

        Handles SIGTERM (container stop) and SIGINT (Ctrl+C) to ensure
        the server shuts down cleanly and releases resources.
        """
        def signal_handler(signum, _frame):
            """Handle shutdown signals gracefully."""
            signal_name = signal.Signals(signum).name
            logger.info(f"Received {signal_name}, initiating graceful shutdown...")
            self.shutdown_requested = True

        # Register handlers for common shutdown signals
        signal.signal(signal.SIGTERM, signal_handler)  # Docker stop
        signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C

    def setup_file_watcher(self):
        """
        Initialize file system monitoring for live configuration reloading.

        Sets up a watchdog observer to monitor the config file directory
        for changes. When changes are detected, triggers a server reload.
        """
        if not self.enable_live_reload:
            return

        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.warning(f"Config file {self.config_path} does not exist, file watching disabled")
                return

            # Watch the directory containing the config file (not the file itself)
            # This handles cases where editors create temp files and rename them
            watch_dir = config_file.parent

            # Create handler and observer
            self.config_handler = ConfigFileHandler(self.config_path, self._request_reload)
            self.file_observer = Observer()
            self.file_observer.schedule(self.config_handler, str(watch_dir), recursive=False)
            self.file_observer.start()

            logger.info(f"✓ File watcher enabled for {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to setup file watcher: {e}")
            # Disable live reload if setup fails
            self.enable_live_reload = False

    def stop_file_watcher(self):
        """
        Clean up file system monitoring resources.

        Stops the watchdog observer and cancels any pending debounce timers.
        """
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            self.file_observer = None

        # Cancel any pending debounce timers
        if self.config_handler and self.config_handler.debounce_timer:
            self.config_handler.debounce_timer.cancel()

        self.config_handler = None

    def _request_reload(self):
        """
        Internal method to request a configuration reload.

        Called by the file watcher when config changes are detected.
        Sets the reload flag which is checked by the monitoring thread.
        """
        if not self.shutdown_requested:
            self.reload_requested = True
            logger.info("Configuration reload requested")

    def load_config_with_retry(self) -> bool:
        """
        Load and validate the MCP configuration with retry logic.

        Implements exponential backoff retry strategy for transient errors
        while immediately failing for permanent errors like file not found.

        Returns:
            bool: True if config was loaded successfully, False otherwise
        """
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Loading configuration from {self.config_path} (attempt {attempt + 1}/{self.max_retries})")

                # Read and parse JSON configuration
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)

                # Validate basic config structure
                if not isinstance(self.config, dict) or 'mcpServers' not in self.config:
                    raise ValueError("Config must contain 'mcpServers' key")

                server_count = len(self.config['mcpServers'])
                logger.info(f"✓ Successfully loaded configuration with {server_count} servers")
                return True

            except FileNotFoundError:
                # File not found is a permanent error - don't retry
                logger.error(f"Configuration file not found: {self.config_path}")
                return False
            except json.JSONDecodeError as e:
                # JSON syntax errors are permanent - don't retry
                logger.error(f"Invalid JSON in config file: {e}")
                return False
            except Exception as e:
                # Other errors might be transient - retry with backoff
                logger.error(f"Config load attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    # Exponential backoff: 1s, 2s, 4s, 8s...
                    backoff_time = 2 ** attempt
                    logger.info(f"Retrying in {backoff_time} seconds...")
                    time.sleep(backoff_time)
                else:
                    logger.error("Failed to load config after all retries")

        return False

    def create_proxy(self) -> bool:
        """
        Create a FastMCP proxy instance from the loaded configuration.

        Uses FastMCP.as_proxy() to create a proxy that can handle multiple
        MCP servers as defined in the configuration.

        Returns:
            bool: True if proxy was created successfully, False otherwise
        """
        try:
            logger.info("Creating MCP proxy...")
            # Create proxy using the loaded configuration dictionary
            self.proxy = FastMCP.as_proxy(self.config, name="MCP Proxy Hub")
            logger.info("✓ MCP proxy created successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to create proxy: {e}", exc_info=True)
            return False

    def run_server(self):
        """Run the server with error handling"""
        try:
            logger.info("Starting MCP proxy server on 0.0.0.0:8080...")
            self.proxy.run(transport="streamable-http", host="0.0.0.0", port=8080)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown_requested = True
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def run_server_with_reload(self):
        """Run server with reload support - triggers process exit on config change"""
        import time

        # For live reload, we'll use a simple approach:
        # When config changes, we exit the process and let the restart mechanism handle it

        try:
            # Start monitoring in a separate thread
            monitor_thread = threading.Thread(target=self._monitor_for_reload, daemon=True)
            monitor_thread.start()

            # Run the server normally
            logger.info("Starting MCP proxy server on 0.0.0.0:8080...")
            self.proxy.run(transport="streamable-http", host="0.0.0.0", port=8080)

        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown_requested = True
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def _monitor_for_reload(self):
        """
        Background thread to monitor for configuration reload requests.

        Runs in a separate daemon thread and checks for reload requests
        from the file watcher. When a reload is requested, triggers a
        process exit with a special code to indicate reload (not crash).
        """
        while not self.shutdown_requested:
            if self.reload_requested:
                logger.info("Config reload detected, triggering process restart...")
                # Force process exit to ensure clean port release
                # Exit code 42 is used to distinguish reload from crash
                os._exit(42)
            time.sleep(0.5)  # Check every 500ms

    def run_with_restart(self):
        """
        Main server loop with automatic restart and error recovery.

        This is the primary method that orchestrates the entire server lifecycle:
        - Sets up signal handlers for graceful shutdown
        - Implements restart logic with exponential backoff
        - Handles both crashes and intentional reloads
        - Manages file watching for live configuration changes
        """
        self.setup_signal_handlers()

        # Display version information at startup
        version_info = get_version_info()
        logger.info(f"Starting MCP Proxy Server v{version_info['full']}")
        logger.info("Starting resilient MCP proxy...")

        restart_count = 0

        # Main server loop - continues until shutdown is requested
        while not self.shutdown_requested:
            try:
                # Step 1: Load and validate configuration
                if not self.load_config_with_retry():
                    logger.error("Cannot start without valid configuration")
                    sys.exit(1)

                # Step 2: Create FastMCP proxy instance
                if not self.create_proxy():
                    logger.error("Cannot start without valid proxy")
                    sys.exit(1)

                # Step 3: Setup file watching for live reload (if enabled)
                self.setup_file_watcher()

                # Step 4: Reset restart metrics on successful startup
                if restart_count > 0:
                    logger.info(f"Successfully restarted after {restart_count} attempts")
                restart_count = 0

                # Step 5: Run the actual server with reload monitoring
                self.run_server_with_reload()

                # Step 6: Clean up resources
                self.stop_file_watcher()

                # If we reach here, server stopped gracefully (not crashed)
                break

            except SystemExit as e:
                # Handle special exit codes from reload mechanism
                if e.code == 42:
                    # Config reload was triggered - restart with new config
                    logger.info("Config reload triggered, restarting with new configuration...")
                    self.stop_file_watcher()
                    restart_count = 0  # Reloads don't count as restart failures

                    # Ensure port is available before restarting
                    if not self.wait_for_port_available():
                        logger.error("Port did not become available, skipping reload")
                        break

                    continue  # Restart the loop with new config
                else:
                    # Normal exit code - shut down gracefully
                    break

            except Exception as e:
                # Handle unexpected crashes
                restart_count += 1
                logger.error(f"Server crashed (restart #{restart_count}): {e}", exc_info=True)

                # Check if shutdown was requested during the crash
                if self.shutdown_requested:
                    logger.info("Shutdown requested, not restarting")
                    break

                # Prevent infinite restart loops
                if restart_count >= 10:
                    logger.error("Too many restart attempts, giving up")
                    sys.exit(1)

                # Implement exponential backoff for restart delay
                logger.info(f"Restarting server in {self.restart_delay} seconds...")
                time.sleep(self.restart_delay)

                # Increase delay for subsequent restarts (max 30 seconds)
                self.restart_delay = min(self.restart_delay * 1.5, 30)

        logger.info("Proxy server shutdown complete")

        # Final cleanup of all resources
        self.stop_file_watcher()

def main():
    """
    Application entry point and configuration setup.

    Reads configuration from environment variables, creates the resilient
    proxy instance, and starts the main server loop. This function handles
    the initial setup and delegates the complex server management to the
    ResilientMCPProxy class.

    Environment Variables:
        MCP_CONFIG_PATH: Path to JSON config file (default: mcp_config.json)
        MCP_MAX_RETRIES: Config load retry attempts (default: 3)
        MCP_RESTART_DELAY: Initial restart delay in seconds (default: 5)
        MCP_LIVE_RELOAD: Enable file watching (default: false)
    """
    # Read configuration from environment variables with sensible defaults
    config_path = os.getenv("MCP_CONFIG_PATH", "mcp_config.json")
    max_retries = int(os.getenv("MCP_MAX_RETRIES", "3"))
    restart_delay = int(os.getenv("MCP_RESTART_DELAY", "5"))

    # Parse boolean environment variable for live reload
    # Accepts: true, 1, yes (case insensitive)
    enable_live_reload = os.getenv("MCP_LIVE_RELOAD", "false").lower() in ("true", "1", "yes")

    # Create and configure the resilient proxy instance
    proxy = ResilientMCPProxy(
        config_path=config_path,
        max_retries=max_retries,
        restart_delay=restart_delay,
        enable_live_reload=enable_live_reload
    )

    # Start the main server loop with all resilience features
    proxy.run_with_restart()


if __name__ == "__main__":
    # Entry point when script is run directly (not imported)
    main()
