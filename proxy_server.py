"""
MCP Proxy Server - A resilient proxy server for Model Context Protocol (MCP) servers.

This module provides a robust proxy server that can manage multiple MCP servers
through a single FastMCP endpoint with Google OAuth authentication. Features:

- Automatic restart on crashes with exponential backoff
- Live configuration reloading via file system monitoring
- Graceful shutdown handling (SIGTERM, SIGINT)
- Port availability checking before restart
- Google OAuth 2.0 authentication (Claude.ai compatible)
- Multi-transport support (stdio, SSE, HTTP)

Environment Variables:
    # Google OAuth (Required)
    GOOGLE_CLIENT_ID: OAuth 2.0 Client ID from Google Cloud Console
    GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret
    MCP_BASE_URL: Public URL for OAuth callbacks
    GOOGLE_JWT_KEY: JWT signing key (optional, recommended for production)

    # MCP Proxy Configuration
    MCP_CONFIG_PATH: Path to MCP servers config (default: mcp_config.json)
    MCP_HOST: Server bind address (default: 0.0.0.0)
    MCP_PORT: Server bind port (default: 8080)
    MCP_LIVE_RELOAD: Enable live config reloading (default: false)

    # Server Resilience
    MCP_MAX_RETRIES: Config load retry attempts (default: 3)
    MCP_RESTART_DELAY: Initial restart delay in seconds (default: 5)
"""

# Core libraries

from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
from starlette.responses import JSONResponse

import os
import sys
import json
import signal
import time
import logging
import threading
import socket
import re
from pathlib import Path
from typing import Optional, Any, Dict, List

# Load .env file if it exists
try:
    from dotenv import load_dotenv
    env_path = Path(".env")
    if env_path.exists():
        load_dotenv(env_path)
        # Log will show after logging is configured
    else:
        # Log will show after logging is configured
        pass
except ImportError:
    pass  # dotenv not installed, env vars must be set manually

# JSON schema validation
import jsonschema

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

# Configure structured logging with environment variable support
def setup_logging():
    """
    Configure structured logging with support for different log levels per logger.
    
    Environment Variables:
        MCP_LOG_LEVEL: Global log level (default: INFO)
                       Values: DEBUG, INFO, WARNING, ERROR, CRITICAL
        MCP_LOG_LEVELS: Comma-separated logger-specific levels (default: none)
                        Format: "logger1:DEBUG,logger2:WARNING,httpx:DEBUG"
    
    Examples:
        MCP_LOG_LEVEL=DEBUG - Enable debug logging globally
        MCP_LOG_LEVELS="fastmcp:DEBUG,httpx:DEBUG" - Debug only fastmcp and httpx
        MCP_LOG_LEVEL=INFO MCP_LOG_LEVELS="fastmcp:DEBUG" - Info globally, debug for fastmcp
    """
    # Standard log format with fixed-width logger name (15 chars) for alignment
    log_format = '%(asctime)s - %(name)-15s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(log_format)
    
    # Create handlers for stdout and stderr
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    
    # Get global log level from environment
    global_level_str = os.getenv("MCP_LOG_LEVEL", "INFO").upper()
    try:
        global_level = getattr(logging, global_level_str)
    except AttributeError:
        global_level = logging.INFO
        print(f"WARNING: Invalid MCP_LOG_LEVEL '{global_level_str}', using INFO", file=sys.stderr)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(global_level)
    root_logger.handlers.clear()
    root_logger.addHandler(stdout_handler)
    root_logger.addHandler(stderr_handler)
    
    # Configure logger-specific levels
    logger_levels_str = os.getenv("MCP_LOG_LEVELS", "")
    if logger_levels_str:
        for logger_config in logger_levels_str.split(","):
            logger_config = logger_config.strip()
            if ":" not in logger_config:
                continue
            
            logger_name, level_str = logger_config.split(":", 1)
            logger_name = logger_name.strip()
            level_str = level_str.strip().upper()
            
            try:
                level = getattr(logging, level_str)
                logger_obj = logging.getLogger(logger_name)
                logger_obj.setLevel(level)
            except AttributeError:
                print(f"WARNING: Invalid log level '{level_str}' for logger '{logger_name}'", file=sys.stderr)

# Run logging setup
setup_logging()
logger = logging.getLogger(__name__)

# Configure loggers for common libraries (will be overridden by MCP_LOG_LEVELS if specified)
logging.getLogger("fastmcp").setLevel(logging.INFO)
logging.getLogger("fastmcp.auth").setLevel(logging.DEBUG)  # Enable auth debug logging
logging.getLogger("fastmcp.server.auth").setLevel(logging.DEBUG)  # Enable auth debug logging
logging.getLogger("httpx").setLevel(logging.INFO)

# Log .env file loading
try:
    from dotenv import load_dotenv
    env_path = Path(".env")
    if env_path.exists():
        abs_env_path = os.path.abspath(env_path)
        logger.info(f"✓ Loaded environment from: {abs_env_path}")
    else:
        logger.info("No .env file found - using environment variables")
except ImportError:
    logger.info("python-dotenv not installed - using environment variables directly")






def create_google_auth() -> Optional[GoogleProvider]:
    """
    Create Google OAuth provider for Claude.ai integration.

    Supports any OIDC-compliant provider via Google Cloud OAuth.
    Claude.ai requires OAuth with DCR support, which FastMCP's GoogleProvider handles.

    Environment Variables:
        GOOGLE_CLIENT_ID: OAuth 2.0 Client ID from Google Cloud Console
        GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret
        MCP_BASE_URL: Public URL of this proxy (for OAuth callback)
        GOOGLE_JWT_KEY: JWT signing key (optional, recommended for production)

    Returns:
        GoogleProvider instance or None if not configured
    """
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    base_url = os.getenv("MCP_BASE_URL")
    jwt_key = os.getenv("GOOGLE_JWT_KEY")

    if not all([client_id, client_secret, base_url]):
        return None

    logger.info("Google OAuth Configuration:")
    logger.info(f"  Client ID: {'*' * 8 + (client_id[-8:] if client_id and len(client_id) > 8 else 'INVALID')}")
    logger.info(f"  Client Secret: {'***REDACTED***' if client_secret else 'MISSING'}")
    logger.info(f"  Base URL: {base_url}")
    logger.info(f"  JWT Key: {'***CONFIGURED***' if jwt_key else 'not set (dev mode)'}")

    try:
        auth = GoogleProvider(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            required_scopes=[
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
            ],
            jwt_signing_key=jwt_key if jwt_key else None,
        )

        logger.info("✓ GoogleProvider successfully initialized")
        return auth

    except Exception as e:
        logger.error(f"✗ Failed to create GoogleProvider: {e}", exc_info=True)
        return None








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

    def __init__(self, config_path: str, max_retries: int = 3, restart_delay: int = 5, enable_live_reload: bool = True, host: str = "0.0.0.0", port: int = 8080):
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
        # Configuration settings
        self.config_path = config_path
        self.max_retries = max_retries
        self.restart_delay = restart_delay
        self.enable_live_reload = enable_live_reload
        self.host = host
        self.port = port

        # Runtime state
        self.proxy: Optional[FastMCP] = None
        self.shutdown_requested = False
        self.reload_requested = False
        self.config = None

        # File watching components
        self.file_observer: Optional[Observer] = None
        self.config_handler: Optional[ConfigFileHandler] = None

    def wait_for_port_available(self, timeout: int = 10):
        """
        Wait for a network port to become available.

        This is crucial for live reloading since the previous server process
        may take time to release the port after termination.

        Args:
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
                    sock.bind((self.host, self.port))
                    logger.info(f"✓ Port {self.port} is available")
                    return True
            except OSError:
                # Port still in use, wait a bit more
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
        Load and validate the MCP configuration with retry logic, including JSON schema validation.

        Implements exponential backoff retry strategy for transient errors
        while immediately failing for permanent errors like file not found or schema validation errors.

        Returns:
            bool: True if config was loaded and validated successfully, False otherwise
        """
        # Schema is always in the same directory as this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        schema_path = os.path.join(script_dir, "mcp_config.schema.json")

        logger.info(f"Loading configuration from: {os.path.abspath(self.config_path)}")

        try:
            with open(schema_path, "r") as sf:
                schema = json.load(sf)
            logger.info(f"✓ Loaded schema from: {schema_path}")
        except Exception as e:
            logger.error(f"✗ Failed to load config schema from {schema_path}: {e}")
            return False

        for attempt in range(self.max_retries):
            try:
                abs_config_path = os.path.abspath(self.config_path)
                logger.info(f"Attempting to load config from {abs_config_path} (attempt {attempt + 1}/{self.max_retries})")

                # Read and parse JSON configuration
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                logger.info(f"✓ Loaded config file from {abs_config_path}")

                # Validate config against schema
                jsonschema.validate(instance=self.config, schema=schema)

                server_count = len(self.config['mcpServers'])
                logger.info(f"✓ Successfully loaded and validated configuration with {server_count} servers")
                return True

            except FileNotFoundError:
                # File not found is a permanent error - don't retry
                logger.error(f"Configuration file not found: {self.config_path}")
                return False
            except json.JSONDecodeError as e:
                # JSON syntax errors are permanent - don't retry
                logger.error(f"Invalid JSON in config file: {e}")
                return False
            except jsonschema.ValidationError as e:
                logger.error(f"Config schema validation failed: {e.message}")
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
        Create a single unified FastMCP proxy with all configured MCP servers aggregated.
        All servers are available through a single /mcp/ endpoint.
        Returns True if proxy created successfully, False otherwise.
        """
        try:
            mcp_servers = self.config.get("mcpServers", {})
            if not mcp_servers:
                logger.error("No MCP servers configured!")
                return False

            # Create Google OAuth provider (required)
            auth = create_google_auth()

            if not auth:
                logger.error("Google OAuth authentication is required but not configured.")
                logger.error("Set these environment variables:")
                logger.error("  - GOOGLE_CLIENT_ID: OAuth 2.0 Client ID")
                logger.error("  - GOOGLE_CLIENT_SECRET: OAuth 2.0 Client Secret")
                logger.error("  - MCP_BASE_URL: Public URL of this proxy")
                logger.error("")
                logger.error("Get credentials from: https://console.developers.google.com/")
                return False

            logger.info("✓ Google OAuth authentication enabled (Claude.ai compatible)")

            # Create SINGLE unified FastMCP instance with all servers
            try:
                proxy_config = {"mcpServers": mcp_servers}
                
                self.proxy = FastMCP.as_proxy(
                    proxy_config,
                    name="mcp-proxy",
                    auth=auth
                )

                # Add health check endpoint
                @self.proxy.custom_route("/health", methods=["GET"])
                async def health_check(request):
                    # If CF-Ray header present, request came through Cloudflare (external)
                    # If no CF-Ray, assume local/Docker request (internal)
                    cf_ray = request.headers.get("CF-Ray")

                    response = {
                        "status": "healthy",
                        "service": "mcp-proxy"
                    }

                    # Only include server list if NOT from Cloudflare (local/internal requests)
                    if not cf_ray:
                        response["servers"] = list(mcp_servers.keys())

                    return JSONResponse(response)

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

    def run_server(self):
        """Run FastMCP server using native HTTP transport."""
        try:
            logger.info(f"Starting unified FastMCP proxy on {self.host}:{self.port}")
            logger.info(f"  Endpoint: / (root)")
            self.proxy.run(
                transport="http",
                host=self.host,
                port=self.port
            )
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown_requested = True
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def run_server_with_reload(self):
        """Run FastMCP server with reload support - triggers process exit on config change"""
        try:
            # Start monitoring in a separate thread
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
            self.shutdown_requested = True
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def _monitor_for_reload(self):
        """
        Background thread to monitor for configuration reload requests.
        When a reload is requested, set a restart_requested flag and shut down the server gracefully.
        """
        while not self.shutdown_requested:
            if self.reload_requested:
                logger.info("Config reload detected, requesting graceful restart...")
                self.restart_requested = True
                # Trigger shutdown of the server (uvicorn)
                import threading
                def shutdown():
                    import sys
                    import os
                    import signal
                    os.kill(os.getpid(), signal.SIGINT)
                threading.Thread(target=shutdown, daemon=True).start()
                break
            time.sleep(0.5)

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

        while not self.shutdown_requested:
            self.restart_requested = False
            try:
                if not self.load_config_with_retry():
                    logger.error("Cannot start without valid configuration")
                    sys.exit(1)

                if not self.create_proxy():
                    logger.error("Cannot start without valid proxy")
                    sys.exit(1)

                self.setup_file_watcher()

                if restart_count > 0:
                    logger.info(f"Successfully restarted after {restart_count} attempts")
                restart_count = 0

                self.run_server_with_reload()

                self.stop_file_watcher()

                # If reload was requested, wait for port and restart
                if self.restart_requested:
                    logger.info("Graceful reload requested, restarting with new configuration...")
                    if not self.wait_for_port_available():
                        logger.error("Port did not become available, skipping reload")
                        break
                    continue
                else:
                    break

            except Exception as e:
                restart_count += 1
                logger.error(f"Server crashed (restart #{restart_count}): {e}", exc_info=True)
                if self.shutdown_requested:
                    logger.info("Shutdown requested, not restarting")
                    break
                if restart_count >= 10:
                    logger.error("Too many restart attempts, giving up")
                    sys.exit(1)
                logger.info(f"Restarting server in {self.restart_delay} seconds...")
                time.sleep(self.restart_delay)
                self.restart_delay = min(self.restart_delay * 1.5, 30)

        logger.info("Proxy server shutdown complete")
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
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8080"))

    # Parse boolean environment variable for live reload
    # Accepts: true, 1, yes (case insensitive)
    enable_live_reload = os.getenv("MCP_LIVE_RELOAD", "false").lower() in ("true", "1", "yes")

    # Create and configure the resilient proxy instance
    proxy = ResilientMCPProxy(
        config_path=config_path,
        max_retries=max_retries,
        restart_delay=restart_delay,
        enable_live_reload=enable_live_reload,
        host=host,
        port=port
    )

    # Start the main server loop with all resilience features
    proxy.run_with_restart()


if __name__ == "__main__":
    # Entry point when script is run directly (not imported)
    main()
