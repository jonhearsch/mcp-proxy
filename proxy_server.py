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
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

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
    """Handles config file change events"""

    def __init__(self, config_path: str, reload_callback):
        self.config_path = Path(config_path).resolve()
        self.reload_callback = reload_callback
        self.debounce_timer = None
        self.debounce_delay = 1.0  # Wait 1 second after last change

    def on_modified(self, event):
        if event.is_directory:
            return

        # Check if the modified file is our config file
        if Path(event.src_path).resolve() == self.config_path:
            self._debounced_reload()

    def on_moved(self, event):
        if event.is_directory:
            return

        # Handle file renames/moves that affect our config
        if Path(event.dest_path).resolve() == self.config_path:
            self._debounced_reload()

    def on_created(self, event):
        if event.is_directory:
            return

        # Handle config file recreation
        if Path(event.src_path).resolve() == self.config_path:
            logger.info(f"Config file {self.config_path} was recreated")
            self._debounced_reload()

    def on_deleted(self, event):
        if event.is_directory:
            return

        # Handle config file deletion
        if Path(event.src_path).resolve() == self.config_path:
            logger.warning(f"Config file {self.config_path} was deleted")
            # Don't trigger reload on deletion - wait for recreation

    def _debounced_reload(self):
        """Debounce rapid file changes to avoid multiple reloads"""
        if self.debounce_timer:
            self.debounce_timer.cancel()

        self.debounce_timer = threading.Timer(self.debounce_delay, self._trigger_reload)
        self.debounce_timer.start()

    def _trigger_reload(self):
        """Trigger the actual reload"""
        logger.info(f"Config file {self.config_path} changed, triggering reload...")
        self.reload_callback()

class ResilientMCPProxy:
    def __init__(self, config_path: str, max_retries: int = 3, restart_delay: int = 5, enable_live_reload: bool = True):
        self.config_path = config_path
        self.max_retries = max_retries
        self.restart_delay = restart_delay
        self.enable_live_reload = enable_live_reload
        self.proxy: Optional[FastMCP] = None
        self.shutdown_requested = False
        self.reload_requested = False
        self.config = None
        self.file_observer: Optional[Observer] = None
        self.config_handler: Optional[ConfigFileHandler] = None

    def wait_for_port_available(self, host: str = "0.0.0.0", port: int = 8080, timeout: int = 10):
        """Wait for port to become available"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((host, port))
                    logger.info(f"✓ Port {port} is available")
                    return True
            except OSError:
                logger.info(f"Port {port} still in use, waiting...")
                time.sleep(0.5)

        logger.warning(f"Port {port} did not become available within {timeout} seconds")
        return False

    def setup_signal_handlers(self):
        """Setup graceful shutdown signal handlers"""
        def signal_handler(signum, _frame):
            signal_name = signal.Signals(signum).name
            logger.info(f"Received {signal_name}, initiating graceful shutdown...")
            self.shutdown_requested = True

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

    def setup_file_watcher(self):
        """Setup file watcher for config changes"""
        if not self.enable_live_reload:
            return

        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.warning(f"Config file {self.config_path} does not exist, file watching disabled")
                return

            # Watch the directory containing the config file
            watch_dir = config_file.parent

            self.config_handler = ConfigFileHandler(self.config_path, self._request_reload)
            self.file_observer = Observer()
            self.file_observer.schedule(self.config_handler, str(watch_dir), recursive=False)
            self.file_observer.start()

            logger.info(f"✓ File watcher enabled for {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to setup file watcher: {e}")
            self.enable_live_reload = False

    def stop_file_watcher(self):
        """Stop the file watcher"""
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            self.file_observer = None

        if self.config_handler and self.config_handler.debounce_timer:
            self.config_handler.debounce_timer.cancel()

        self.config_handler = None

    def _request_reload(self):
        """Request a configuration reload"""
        if not self.shutdown_requested:
            self.reload_requested = True
            logger.info("Configuration reload requested")

    def load_config_with_retry(self) -> bool:
        """Load configuration with retry logic and exponential backoff"""
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Loading configuration from {self.config_path} (attempt {attempt + 1}/{self.max_retries})")

                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)

                # Validate config structure
                if not isinstance(self.config, dict) or 'mcpServers' not in self.config:
                    raise ValueError("Config must contain 'mcpServers' key")

                logger.info(f"✓ Successfully loaded configuration with {len(self.config['mcpServers'])} servers")
                return True

            except FileNotFoundError:
                logger.error(f"Configuration file not found: {self.config_path}")
                return False
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in config file: {e}")
                return False
            except Exception as e:
                logger.error(f"Config load attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    backoff_time = 2 ** attempt
                    logger.info(f"Retrying in {backoff_time} seconds...")
                    time.sleep(backoff_time)
                else:
                    logger.error("Failed to load config after all retries")

        return False

    def create_proxy(self) -> bool:
        """Create FastMCP proxy with error handling"""
        try:
            logger.info("Creating MCP proxy...")
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
        """Monitor for reload requests in background thread"""
        import time

        while not self.shutdown_requested:
            if self.reload_requested:
                logger.info("Config reload detected, triggering process restart...")
                # Force exit to trigger restart at the process level
                os._exit(42)  # Use special exit code to indicate reload
            time.sleep(0.5)

    def run_with_restart(self):
        """Main server loop with automatic restart capability"""
        self.setup_signal_handlers()
        logger.info("Starting resilient MCP proxy...")

        restart_count = 0

        while not self.shutdown_requested:
            try:
                # Load configuration
                if not self.load_config_with_retry():
                    logger.error("Cannot start without valid configuration")
                    sys.exit(1)

                # Create proxy
                if not self.create_proxy():
                    logger.error("Cannot start without valid proxy")
                    sys.exit(1)

                # Setup file watcher after successful proxy creation
                self.setup_file_watcher()

                # Reset restart count on successful startup
                if restart_count > 0:
                    logger.info(f"Successfully restarted after {restart_count} attempts")
                restart_count = 0

                # Run the server with reload checking
                self.run_server_with_reload()

                # Clean up file watcher
                self.stop_file_watcher()

                # If we reach here, server stopped gracefully
                break

            except SystemExit as e:
                # Handle special exit codes
                if e.code == 42:
                    logger.info("Config reload triggered, restarting with new configuration...")
                    self.stop_file_watcher()
                    restart_count = 0  # Reset restart count for reloads

                    # Wait for port to become available
                    if not self.wait_for_port_available():
                        logger.error("Port did not become available, skipping reload")
                        break

                    continue
                else:
                    # Normal exit
                    break

            except Exception as e:
                restart_count += 1
                logger.error(f"Server crashed (restart #{restart_count}): {e}", exc_info=True)

                if self.shutdown_requested:
                    logger.info("Shutdown requested, not restarting")
                    break

                # Limit restart attempts to prevent infinite loops
                if restart_count >= 10:
                    logger.error("Too many restart attempts, giving up")
                    sys.exit(1)

                logger.info(f"Restarting server in {self.restart_delay} seconds...")
                time.sleep(self.restart_delay)

                # Increase delay for subsequent restarts (max 30s)
                self.restart_delay = min(self.restart_delay * 1.5, 30)

        logger.info("Proxy server shutdown complete")

        # Final cleanup
        self.stop_file_watcher()

def main():
    """Main entry point"""
    config_path = os.getenv("MCP_CONFIG_PATH", "mcp_config.json")
    max_retries = int(os.getenv("MCP_MAX_RETRIES", "3"))
    restart_delay = int(os.getenv("MCP_RESTART_DELAY", "5"))
    enable_live_reload = os.getenv("MCP_LIVE_RELOAD", "false").lower() in ("true", "1", "yes")

    proxy = ResilientMCPProxy(
        config_path=config_path,
        max_retries=max_retries,
        restart_delay=restart_delay,
        enable_live_reload=enable_live_reload
    )

    proxy.run_with_restart()

if __name__ == "__main__":
    main()
