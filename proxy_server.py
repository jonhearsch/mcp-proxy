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
    MCP_PATH_PREFIX: Custom path prefix for MCP endpoint (default: none, endpoint at /mcp/)
"""

# Core libraries

from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier
from fastapi import FastAPI

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
from typing import Optional, Any, Dict, List, Union

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


def expand_env_vars(value: Any) -> Any:
    """
    Recursively expand environment variables in configuration values.
    
    Supports ${VAR_NAME} syntax for environment variable substitution.
    Falls back to empty string if variable is not set.
    
    Args:
        value: Configuration value to expand (can be str, dict, list, or other)
        
    Returns:
        Value with environment variables expanded
        
    Examples:
        "${HOME}/data" -> "/Users/jon/data"
        {"key": "${API_KEY}"} -> {"key": "actual-api-key-value"}
        ["${VAR1}", "${VAR2}"] -> ["value1", "value2"]
    """
    if isinstance(value, str):
        # Pattern matches ${VAR_NAME} with optional fallback ${VAR_NAME:-default}
        def replace_var(match):
            var_name = match.group(1)
            default_value = match.group(2) if match.lastindex >= 2 else ""
            env_value = os.getenv(var_name)
            
            if env_value is None:
                if default_value:
                    logger.debug(f"Environment variable ${{{var_name}}} not set, using default: {default_value}")
                    return default_value
                else:
                    logger.warning(f"Environment variable ${{{var_name}}} not set, using empty string")
                    return ""
            
            return env_value
        
        # Support both ${VAR} and ${VAR:-default} syntax
        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*?)(?::-([^}]*))?\}', replace_var, value)
    
    elif isinstance(value, dict):
        return {key: expand_env_vars(val) for key, val in value.items()}
    
    elif isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    
    else:
        # Return as-is for other types (int, bool, None, etc.)
        return value


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

    def __init__(self, config_path: str, max_retries: int = 3, restart_delay: int = 5, enable_live_reload: bool = True, path_prefix: str = "", host: str = "0.0.0.0", port: int = 8080):
        """
        Initialize the resilient MCP proxy.

        Args:
            config_path: Path to the JSON configuration file
            max_retries: Maximum number of retries for config loading
            restart_delay: Initial delay between restarts (seconds)
            enable_live_reload: Whether to enable live config reloading
            path_prefix: Optional URL path prefix (e.g., "abc123" creates /abc123/mcp/ endpoints)
            host: Host address to bind to (default: 0.0.0.0)
            port: Port number to bind to (default: 8080)
        """
        # Configuration settings
        self.config_path = config_path
        self.max_retries = max_retries
        self.restart_delay = restart_delay
        self.enable_live_reload = enable_live_reload
        self.path_prefix = f"/{path_prefix.strip('/')}" if path_prefix else ""
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
        
        try:
            with open(schema_path, "r") as sf:
                schema = json.load(sf)
        except Exception as e:
            logger.error(f"Failed to load config schema from {schema_path}: {e}")
            return False

        for attempt in range(self.max_retries):
            try:
                logger.info(f"Loading configuration from {self.config_path} (attempt {attempt + 1}/{self.max_retries})")

                # Read and parse JSON configuration
                with open(self.config_path, 'r') as f:
                    raw_config = json.load(f)

                # Expand environment variables in the config
                self.config = expand_env_vars(raw_config)

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
        Create a FastAPI root app and mount a FastMCP proxy instance for each configured MCP server.
        Each server is available at /mcp/{server_name}/
        Returns True if all proxies created successfully, False otherwise.
        """
        try:
            logger.info("Creating FastAPI root app and per-server FastMCP proxies...")
            from starlette.requests import Request
            from starlette.responses import JSONResponse
            from contextlib import asynccontextmanager

            mcp_servers = self.config.get("mcpServers", {})
            if not mcp_servers:
                logger.error("No MCP servers configured!")
                return False

            # Auth: enabled by default unless MCP_DISABLE_AUTH=true
            disable_auth = os.getenv("MCP_DISABLE_AUTH", "false").lower() in ("true", "1", "yes")
            auth = None
            
            if not disable_auth:
                token = os.getenv("MCP_BEARER_TOKEN")
                if not token:
                    logger.error("=" * 80)
                    logger.error("SECURITY ERROR: MCP_BEARER_TOKEN environment variable is required!")
                    logger.error("=" * 80)
                    logger.error("")
                    logger.error("Authentication is enabled but no bearer token is configured.")
                    logger.error("This would expose your MCP servers without authentication.")
                    logger.error("")
                    logger.error("To fix this, choose ONE of the following options:")
                    logger.error("")
                    logger.error("  Option 1 (RECOMMENDED): Set a secure bearer token")
                    logger.error("    export MCP_BEARER_TOKEN=$(openssl rand -hex 32)")
                    logger.error("    OR add to docker-compose.yml:")
                    logger.error("      environment:")
                    logger.error("        - MCP_BEARER_TOKEN=your-secure-token-here")
                    logger.error("")
                    logger.error("  Option 2 (NOT RECOMMENDED): Disable authentication")
                    logger.error("    export MCP_DISABLE_AUTH=true")
                    logger.error("    OR add to docker-compose.yml:")
                    logger.error("      environment:")
                    logger.error("        - MCP_DISABLE_AUTH=true")
                    logger.error("")
                    logger.error("=" * 80)
                    return False
                
                auth = StaticTokenVerifier(tokens={token: {
                    "client_id": "mcp-proxy-client",
                    "scopes": ["*"]
                }})
                logger.info("✓ Bearer token authentication enabled")
            else:
                logger.warning("⚠️  WARNING: Authentication is DISABLED - server is not protected!")

            # Store MCP apps and their lifespans to combine them
            mcp_apps = []

            # Mount each MCP server as its own FastMCP instance
            for name, server_cfg in mcp_servers.items():
                mount_path = f"{self.path_prefix}/mcp/{name}"
                logger.info(f"Mounting MCP server '{name}' at {mount_path}/")
                # Each server gets its own FastMCP proxy
                single_cfg = {"mcpServers": {name: server_cfg}}
                mcp_proxy = FastMCP.as_proxy(single_cfg, name=f"MCP Proxy: {name}", auth=auth)
                # Get the ASGI app from the proxy with path='/' so it uses the mount point as the base
                mcp_app = mcp_proxy.http_app(path='/')
                mcp_apps.append((mount_path, mcp_app))

            # Create a combined lifespan that manages all MCP app lifespans
            @asynccontextmanager
            async def combined_lifespan(app: FastAPI):
                # Start all MCP apps
                async_contexts = []
                for mount_path, mcp_app in mcp_apps:
                    if hasattr(mcp_app, 'lifespan') and mcp_app.lifespan:
                        ctx = mcp_app.lifespan(mcp_app)
                        async_contexts.append(ctx)
                        await ctx.__aenter__()
                
                yield
                
                # Stop all MCP apps in reverse order
                for ctx in reversed(async_contexts):
                    await ctx.__aexit__(None, None, None)

            # Create FastAPI app with combined lifespan
            self.proxy = FastAPI(title="MCP Proxy Hub", lifespan=combined_lifespan)

            # Add a health check endpoint BEFORE mounting sub-apps
            health_path = f"{self.path_prefix}/health"
            
            @self.proxy.get(health_path)
            async def health_check(request: Request):
                version_info = get_version_info()
                return JSONResponse({
                    "status": "healthy",
                    "version": version_info["full"],
                    "servers": list(mcp_servers.keys()),
                    "path_prefix": self.path_prefix if self.path_prefix else None
                })

            # Now mount all the MCP apps
            for mount_path, mcp_app in mcp_apps:
                self.proxy.mount(mount_path, mcp_app)

            logger.info(f"✓ All MCP servers mounted as sub-apps.")
            if self.path_prefix:
                logger.info(f"✓ Path prefix '{self.path_prefix}' applied to all endpoints")
            return True
        except Exception as e:
            logger.error(f"Failed to create per-server proxies: {e}", exc_info=True)
            return False

    def run_server(self):
        """Run the FastAPI root app using uvicorn."""
        try:
            import uvicorn
            logger.info(f"Starting FastAPI root app on {self.host}:{self.port} (all MCP servers at {self.path_prefix or ''}/mcp/{{name}}/)")
            uvicorn.run(self.proxy, host=self.host, port=self.port, log_level="info")
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
            self.shutdown_requested = True
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
            raise

    def run_server_with_reload(self):
        """Run FastAPI root app with reload support - triggers process exit on config change"""
        import time
        try:
            import uvicorn
            # Start monitoring in a separate thread
            monitor_thread = threading.Thread(target=self._monitor_for_reload, daemon=True)
            monitor_thread.start()
            logger.info(f"Starting FastAPI root app on {self.host}:{self.port} (all MCP servers at {self.path_prefix or ''}/mcp/{{name}}/)")
            uvicorn.run(self.proxy, host=self.host, port=self.port, log_level="info")
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
        MCP_PATH_PREFIX: Custom path prefix (default: none, creates /mcp/ endpoint)
                         Example: "3434dc5d-349b-401c-8071-7589df9a0bce" creates /3434dc5d-349b-401c-8071-7589df9a0bce/mcp/
    """
    # Read configuration from environment variables with sensible defaults
    config_path = os.getenv("MCP_CONFIG_PATH", "mcp_config.json")
    max_retries = int(os.getenv("MCP_MAX_RETRIES", "3"))
    restart_delay = int(os.getenv("MCP_RESTART_DELAY", "5"))
    path_prefix = os.getenv("MCP_PATH_PREFIX", "")
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
        path_prefix=path_prefix,
        host=host,
        port=port
    )

    # Start the main server loop with all resilience features
    proxy.run_with_restart()


if __name__ == "__main__":
    # Entry point when script is run directly (not imported)
    main()
