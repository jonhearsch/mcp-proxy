# Coding Conventions

**Analysis Date:** 2026-05-30

## Naming Patterns

**Files:**
- `snake_case` for all Python files: `proxy_server.py`, `version.py`
- Config files use `snake_case` with descriptive suffixes: `mcp_config.json`, `mcp_config.schema.json`, `mcp_config_dev.json`

**Classes:**
- `PascalCase`: `ResilientMCPProxy`, `ConfigFileHandler`
- Acronyms uppercased: `MCP`, `HTTP`, `SSE`

**Functions/Methods:**
- `snake_case`: `create_google_auth()`, `load_config_with_retry()`, `wait_for_port_available()`
- Private methods prefixed with `_`: `_debounced_reload()`, `_trigger_reload()`, `_request_reload()`, `_monitor_for_reload()`
- `_parse_int_env()` — module-level private utility

**Variables:**
- `snake_case` throughout: `config_path`, `max_retries`, `restart_delay`, `global_level_str`
- Constants from `os.getenv()` stored in `UPPER_SNAKE_CASE` env var names

**Type Hints:**
- Used on all public function signatures
- `Optional[T]` from `typing` for nullable return values: `Optional[GoogleProvider]`, `Optional[FastMCP]`
- Full imports: `from typing import Optional, Any, Dict, List`
- Return type annotations on all non-trivial methods: `-> bool`, `-> Optional[GoogleProvider]`

## Module Structure Pattern

```python
"""Module docstring with full description, features list, and environment variables."""

# Core libraries (stdlib)
import os, sys, json, signal, time, logging, threading, socket, re
from pathlib import Path
from typing import Optional, Any, Dict, List

# Load .env early (before logging setup)
try:
    from dotenv import load_dotenv
    ...
except ImportError:
    pass

# Third-party imports
import jsonschema
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Local imports
from version import get_version, get_version_info

# Module-level setup (logging, constants)
setup_logging()
logger = logging.getLogger(__name__)

# Functions, then Classes, then main()

if __name__ == "__main__":
    main()
```

## Docstring Style

**Module-level:** Full module docstring with description, feature list, and env var table:
```python
"""
MCP Proxy Server - A resilient proxy server...

This module provides...

- Feature 1
- Feature 2

Environment Variables:
    VAR_NAME: Description (default: value)
"""
```

**Class-level:** Describes the class purpose, features list:
```python
"""
A resilient MCP proxy server with automatic restart...

This class manages...
- Feature 1
- Feature 2
"""
```

**Method-level:** Short one-liner or Args/Returns sections:
```python
def load_config_with_retry(self) -> bool:
    """
    Load and validate the MCP configuration with retry logic.

    Implements exponential backoff...

    Returns:
        bool: True if config was loaded and validated successfully, False otherwise
    """
```

**Short private methods** use single-line docstrings:
```python
def _trigger_reload(self):
    """Execute the actual reload callback."""
```

## Import Organization

**Order:**
1. Third-party framework imports at top of file (`fastmcp`, `starlette`)
2. Stdlib imports grouped together (`os`, `sys`, `json`, `signal`, `time`, `logging`, `threading`, `socket`, `re`, `pathlib`, `typing`)
3. Optional imports in `try/except ImportError` blocks
4. Remaining third-party imports (`jsonschema`, `watchdog`)
5. Local imports (`version`)

**No path aliases used** — direct imports only.

## Error Handling

**Pattern: Explicit error categorization with different retry strategies:**

```python
except FileNotFoundError:
    # Permanent error - no retry
    logger.error(f"Configuration file not found: {self.config_path}")
    return False
except json.JSONDecodeError as e:
    # Permanent error - no retry
    logger.error(f"Invalid JSON in config file: {e}")
    return False
except Exception as e:
    # Transient error - retry with backoff
    logger.error(f"Config load attempt {attempt + 1} failed: {e}")
```

**Pattern: `exc_info=True` on unexpected exceptions:**
```python
logger.error(f"Failed to create GoogleProvider: {e}", exc_info=True)
```

**Pattern: Boolean return for success/failure from setup methods:**
```python
def create_proxy(self) -> bool:
    ...
    return True   # success
    return False  # failure
```

**Pattern: Optional return for factory functions:**
```python
def create_google_auth() -> Optional[GoogleProvider]:
    if not all([client_id, client_secret, base_url]):
        return None
    ...
    return auth
```

**Pattern: Graceful degradation — disable feature rather than crash:**
```python
except Exception as e:
    logger.error(f"Failed to setup file watcher: {e}")
    self.enable_live_reload = False  # Disable instead of raising
```

## Logging

**Framework:** Standard `logging` module with a custom `setup_logging()` function.

**Logger per module:**
```python
logger = logging.getLogger(__name__)
```

**Log format:**
```
%(asctime)s - %(name)-15s - %(levelname)s - %(message)s
```
Fixed-width logger name field (15 chars) for alignment.

**Stdout/stderr split:**
- `INFO` and below → `sys.stdout`
- `WARNING` and above → `sys.stderr`

**Visual status markers in log messages:**
- `✓` prefix for success: `logger.info("✓ GoogleProvider successfully initialized")`
- `✗` prefix for failure: `logger.error("✗ Failed to create GoogleProvider: {e}")`
- Indented details under parent log: `logger.info(f"  Client ID: ...")`

**Severity usage:**
- `logger.info()` — normal lifecycle events, configuration details
- `logger.warning()` — non-fatal conditions (file deleted, port still in use)
- `logger.error()` — failures that prevent operation (bad config, missing auth)
- `logger.error(..., exc_info=True)` — exceptions with full traceback

**Environment-configurable levels:**
- `MCP_LOG_LEVEL` — global level override
- `MCP_LOG_LEVELS` — per-logger overrides (`"fastmcp:DEBUG,httpx:DEBUG"`)

## Boolean Environment Variable Parsing

Standard pattern:
```python
enable_live_reload = os.getenv("MCP_LIVE_RELOAD", "false").lower() in ("true", "1", "yes")
```

## Integer Environment Variable Parsing

Utility function:
```python
def _parse_int_env(name: str, default: int) -> int:
    """Parse an integer environment variable with a friendly fallback on invalid input."""
    val = os.getenv(name, str(default))
    try:
        return int(val)
    except ValueError:
        logger.warning(f"Invalid value for {name}='{val}', using default {default}")
        return default
```

## Exponential Backoff Pattern

```python
for attempt in range(self.max_retries):
    try:
        ...
        return True
    except TransientError:
        if attempt < self.max_retries - 1:
            backoff_time = 2 ** attempt  # 1s, 2s, 4s, 8s...
            logger.info(f"Retrying in {backoff_time} seconds...")
            time.sleep(backoff_time)
```

Restart delay uses multiplicative backoff with cap:
```python
self.restart_delay = min(self.restart_delay * 1.5, 30)
```

## Comment Style

- Inline comments explain *why*, not *what*
- Section comments group code blocks: `# Runtime state`, `# File watching components`
- Multi-line logic uses descriptive comments before each significant block
- Security-sensitive values are redacted in logs with explicit comments

## Code Organization

- Module-level setup code (logging, env loading) runs at import time
- `main()` function at module bottom contains only orchestration, no business logic
- `if __name__ == "__main__": main()` entry point guard always present
- Class `__init__` groups instance variables into labeled comment sections

---

*Convention analysis: 2026-05-30*
