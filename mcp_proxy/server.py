"""
MCP Proxy Server — main server module.

Contains ResilientMCPProxy and main() entry point.
Logging is configured via mcp_proxy.logging.configure_logging().
"""

import os
import sys
import json
import signal
import time
import threading
import socket
import re
from pathlib import Path
from typing import Optional, Any, Dict, List

# Load .env file if it exists (track result for post-setup logging)
_dotenv_loaded = False
_dotenv_path = None
_dotenv_available = False
try:
    from dotenv import load_dotenv as _load_dotenv
    _dotenv_available = True
    _env_path = Path(".env")
    if _env_path.exists():
        _load_dotenv(_env_path)
        _dotenv_loaded = True
        _dotenv_path = os.path.abspath(_env_path)
except ImportError:
    pass

# JSON schema validation
import jsonschema

# File watching for live reload
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Version information
try:
    from version import get_version, get_version_info
except ImportError:
    def get_version():
        return "unknown"
    def get_version_info():
        return {"full": "unknown"}

from fastmcp import FastMCP
from starlette.responses import JSONResponse

from mcp_proxy.config import load_config_with_retry, _parse_int_env, _parse_bool_env
from mcp_proxy.auth import create_google_auth, create_static_token_auth
from mcp_proxy.watcher import ConfigFileHandler
from mcp_proxy.logging import configure_logging, get_logger


# Run logging setup
configure_logging(
    log_level_str=os.getenv("MCP_LOG_LEVEL", "INFO"),
    per_logger_str=os.getenv("MCP_LOG_LEVELS", ""),
)
logger = get_logger(__name__)

# Log .env loading result (now that logging is configured)
if _dotenv_available:
    if _dotenv_loaded:
        logger.info(f"✓ Loaded environment from: {_dotenv_path}")
    else:
        logger.info("No .env file found - using environment variables")
else:
    logger.info("python-dotenv not installed - using environment variables directly")

# Configure loggers for common libraries (handled in configure_logging, including MCP_AUTH_DEBUG)


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

    def __init__(
        self,
        config_path: str,
        max_retries: int = 3,
        restart_delay: int = 5,
        enable_live_reload: bool = True,
        host: str = "0.0.0.0",
        port: int = 8080,
    ):
        """
        Initialize the resilient MCP proxy.

        Args:
            config_path: Path to the JSON configuration file
            max_retries: Maximum number of retries for config loading
            restart_delay: Initial delay between restarts (seconds)
            enable_live_reload: Whether to enable live config reloading
            host: Host address to bind to (default: 0.0.0.0)
            port: Port number to bind to (default: 8080)
        """
        self.config_path = config_path
        self.max_retries = max_retries
        self.restart_delay = restart_delay
        self.enable_live_reload = enable_live_reload
        self.host = host
        self.port = port

        self.proxy: Optional[FastMCP] = None
        self.shutdown_event = threading.Event()
        self.reload_event = threading.Event()
        self.restart_event = threading.Event()
        self.config = None

        self.file_observer: Optional[Observer] = None
        self.config_handler: Optional[ConfigFileHandler] = None

    def wait_for_port_available(self, timeout: int = 10):
        """
        Wait for a network port to become available.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            bool: True if port becomes available, False on timeout
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((self.host, self.port))
                    logger.info(f"✓ Port {self.port} is available")
                    return True
            except OSError:
                logger.info(f"Port {self.port} still in use, waiting...")
                time.sleep(0.5)

        logger.warning(f"Port {self.port} did not become available within {timeout} seconds")
        return False

    def setup_signal_handlers(self):
        """
        Configure signal handlers for graceful shutdown.

        Handles SIGTERM (container stop) and SIGINT (Ctrl+C) to ensure
        the server shuts down cleanly and releases resources.
        """
        signal.signal(signal.SIGINT, self._handle_signal)   # Ctrl+C
        signal.signal(signal.SIGTERM, self._handle_signal)  # Docker stop

    def _handle_signal(self, signum, _frame):
        """
        Shared SIGINT/SIGTERM handler.

        _monitor_for_reload() also sends the process SIGTERM to unblock the
        in-progress proxy.run() call for a live reload. It sets restart_event
        before doing so, which lets us tell that self-inflicted signal apart
        from a real external shutdown request (Ctrl+C, Docker/K8s stop) --
        otherwise every reload would set shutdown_event and terminate the
        server instead of restarting it.
        """
        signal_name = signal.Signals(signum).name
        if self.restart_event.is_set():
            logger.info(f"Received {signal_name} for internal reload, not a shutdown")
            return
        logger.info(f"Received {signal_name}, initiating graceful shutdown...")
        self.shutdown_event.set()

    def setup_file_watcher(self):
        """
        Initialize file system monitoring for live configuration reloading.
        """
        if not self.enable_live_reload:
            return

        try:
            config_file = Path(self.config_path)
            if not config_file.exists():
                logger.warning(
                    f"Config file {self.config_path} does not exist, file watching disabled"
                )
                return

            watch_dir = config_file.parent

            self.config_handler = ConfigFileHandler(
                self.config_path, self._request_reload, logger
            )
            self.file_observer = Observer()
            self.file_observer.schedule(self.config_handler, str(watch_dir), recursive=False)
            self.file_observer.start()

            logger.info(f"✓ File watcher enabled for {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to setup file watcher: {e}")
            self.enable_live_reload = False

    def stop_file_watcher(self):
        """Clean up file system monitoring resources."""
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()
            self.file_observer = None

        if self.config_handler and self.config_handler.debounce_timer:
            self.config_handler.debounce_timer.cancel()

        self.config_handler = None

    def _request_reload(self):
        """
        Internal method to request a configuration reload.
        """
        if not self.shutdown_event.is_set():
            self.reload_event.set()
            logger.info("Configuration reload requested")

    def create_proxy(self) -> bool:
        """
        Create a single unified FastMCP proxy with all configured MCP servers aggregated.
        Returns True if proxy created successfully, False otherwise.
        """
        try:
            mcp_servers = self.config.get("mcpServers", {})
            if not mcp_servers:
                logger.error("No MCP servers configured!")
                return False

            # Auth mode selection, in strict precedence order. Exactly one mode
            # is active and it is always logged.
            if _parse_bool_env("MCP_DISABLE_AUTH"):
                # Mode 1: no authentication at all (local debugging only).
                auth = None
                logger.warning(
                    "⚠ Authentication DISABLED (MCP_DISABLE_AUTH set) - do not expose this proxy"
                )

            elif os.getenv("MCP_AUTH_TOKEN"):
                # Mode 2: shared static token, for deployments behind a gateway
                # that terminates the real OAuth flow.
                auth = create_static_token_auth(logger)
                if not auth:
                    # The token was set but rejected (e.g. too short). Fail here
                    # rather than falling through to OAuth -- silently switching
                    # auth modes on a misconfiguration would be a nasty surprise.
                    logger.error("Static token authentication is configured but invalid.")
                    return False
                logger.info("✓ Static token authentication enabled (gateway-fronted mode)")

            else:
                # Mode 3: Google OAuth, for clients connecting directly.
                auth = create_google_auth(logger)
                if not auth:
                    logger.error("Google OAuth authentication is required but not configured.")
                    logger.error("Set these environment variables:")
                    logger.error("  - GOOGLE_CLIENT_ID: OAuth 2.0 Client ID")
                    logger.error("  - GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret")
                    logger.error("  - MCP_BASE_URL: Public URL of this proxy")
                    logger.error("")
                    logger.error("Get credentials from: https://console.developers.google.com/")
                    logger.error("")
                    logger.error(
                        "Alternatively, set MCP_AUTH_TOKEN to run behind a gateway "
                        "that handles OAuth."
                    )
                    return False
                logger.info("✓ Google OAuth authentication enabled (Claude.ai compatible)")

            try:
                proxy_config = {"mcpServers": mcp_servers}

                self.proxy = FastMCP.as_proxy(
                    proxy_config,
                    name="mcp-proxy",
                    auth=auth
                )

                @self.proxy.custom_route("/health", methods=["GET"])
                async def health_check(request):
                    return JSONResponse({"status": "healthy", "service": "mcp-proxy"})

                server_count = len(mcp_servers)
                server_names = ", ".join(mcp_servers.keys())
                logger.info(f"✓ Created unified FastMCP proxy with {server_count} server(s)")
                logger.info(f"  Servers: {server_names}")
                logger.info(f"  Endpoints: /mcp/ (MCP), /health (health check)")

                return True

            except Exception as e:
                logger.error(f"Failed to create FastMCP proxy: {e}", exc_info=True)
                return False

        except Exception as e:
            logger.error(f"Failed to create proxy: {e}", exc_info=True)
            return False

    def run_server_with_reload(self):
        """Run FastMCP server with reload support - triggers process exit on config change"""
        try:
            monitor_thread = threading.Thread(target=self._monitor_for_reload, daemon=True)
            monitor_thread.start()
            logger.info(f"Starting unified FastMCP proxy on {self.host}:{self.port} with live reload")
            logger.info(f"  Endpoint: / (root)")
            self.proxy.run(
                transport="http",
                host=self.host,
                port=self.port
            )
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown_event.set()
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def _monitor_for_reload(self):
        """
        Background thread to monitor for configuration reload requests.
        When a reload is requested, set a restart_requested flag and shut down the server gracefully.
        """
        while not self.shutdown_event.is_set():
            if self.reload_event.wait(timeout=0.5):
                logger.info("Config change detected — sending SIGTERM for graceful reload...")
                self.restart_event.set()
                os.kill(os.getpid(), signal.SIGTERM)
                break

    def _sleep_backoff(self, current_delay: float) -> float:
        """Sleep for current_delay seconds and return the escalated delay (capped at 30s)."""
        time.sleep(current_delay)
        return min(current_delay * 1.5, 30)

    def run_with_restart(self):
        """
        Main server loop with automatic restart and error recovery.
        Implements graceful reload instead of os._exit().
        """
        self.setup_signal_handlers()

        version_info = get_version_info()
        logger.info(f"Starting MCP Proxy Server v{version_info['full']}")
        logger.info("Starting resilient MCP proxy...")

        restart_count = 0
        # self.restart_delay is the configured *initial* delay and is never
        # mutated -- current_delay is the escalating backoff for this
        # crash/retry streak, reset to the initial value after any clean run.
        current_delay = self.restart_delay

        while not self.shutdown_event.is_set():
            self.restart_event.clear()
            self.reload_event.clear()
            try:
                success, config = load_config_with_retry(
                    self.config_path, self.max_retries, logger
                )
                if not success:
                    logger.error("Cannot start without valid configuration")
                    break
                self.config = config

                if not self.create_proxy():
                    logger.error("Cannot start without valid proxy")
                    break

                self.setup_file_watcher()

                if restart_count > 0:
                    logger.info(f"Successfully restarted after {restart_count} attempts")
                restart_count = 0
                current_delay = self.restart_delay

                self.run_server_with_reload()

                self.stop_file_watcher()

                if self.restart_event.is_set():
                    logger.info("Graceful reload requested, restarting with new configuration...")
                    if not self.wait_for_port_available():
                        restart_count += 1
                        logger.error(
                            f"Port did not become available after reload "
                            f"(attempt #{restart_count})"
                        )
                        if self.shutdown_event.is_set():
                            logger.info("Shutdown requested, not retrying")
                            break
                        if restart_count >= 10:
                            logger.error("Too many restart attempts, giving up")
                            break
                        logger.info(f"Retrying reload in {current_delay} seconds...")
                        current_delay = self._sleep_backoff(current_delay)
                    continue
                else:
                    break

            except Exception as e:
                restart_count += 1
                logger.error(f"Server crashed (restart #{restart_count}): {e}", exc_info=True)
                if self.shutdown_event.is_set():
                    logger.info("Shutdown requested, not restarting")
                    break
                if restart_count >= 10:
                    logger.error("Too many restart attempts, giving up")
                    break
                logger.info(f"Restarting server in {current_delay} seconds...")
                current_delay = self._sleep_backoff(current_delay)

        logger.info("Proxy server shutdown complete")
        self.stop_file_watcher()


def main():
    """
    Application entry point and configuration setup.

    Reads configuration from environment variables, creates the resilient
    proxy instance, and starts the main server loop.

    Environment Variables:
        MCP_CONFIG_PATH: Path to JSON config file (default: mcp_config.json)
        MCP_MAX_RETRIES: Config load retry attempts (default: 3)
        MCP_RESTART_DELAY: Initial restart delay in seconds (default: 5)
        MCP_LIVE_RELOAD: Enable file watching (default: false)
    """
    config_path = os.getenv("MCP_CONFIG_PATH", "mcp_config.json")
    max_retries = _parse_int_env("MCP_MAX_RETRIES", 3)
    restart_delay = _parse_int_env("MCP_RESTART_DELAY", 5)
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = _parse_int_env("MCP_PORT", 8080)

    enable_live_reload = _parse_bool_env("MCP_LIVE_RELOAD", False)

    proxy = ResilientMCPProxy(
        config_path=config_path,
        max_retries=max_retries,
        restart_delay=restart_delay,
        enable_live_reload=enable_live_reload,
        host=host,
        port=port
    )

    proxy.run_with_restart()
    if not proxy.shutdown_event.is_set():
        sys.exit(1)


if __name__ == "__main__":
    main()
