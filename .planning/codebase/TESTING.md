# Testing Patterns

**Analysis Date:** 2026-05-30

## Test Framework

**Runner:** None detected — no test framework is installed or configured.

**Test Files:** None found in the repository.

**Config:** No `pytest.ini`, `pyproject.toml`, `setup.cfg`, or `tox.ini` detected.

**Run Commands:**
```bash
# No test runner configured
# No test commands defined in CI/CD pipeline
```

## Current Test Coverage

**Coverage:** 0% — the project has no automated tests.

The CI/CD pipeline (`.github/workflows/docker-build.yml`) performs only version bumping and Docker image builds. There are no test jobs, no `pytest` runs, and no coverage reporting.

## Testability Analysis

The codebase has several characteristics that affect testability:

**Testable patterns present:**
- `ResilientMCPProxy` accepts constructor injection for all config (`config_path`, `host`, `port`, etc.) — easy to instantiate in tests
- `load_config_with_retry()` returns a `bool` — straightforward to assert
- `create_proxy()` returns a `bool` — straightforward to assert
- `wait_for_port_available()` returns a `bool`
- `_parse_int_env()` is a pure utility function — trivially unit-testable
- `get_version()` and `get_version_info()` in `version.py` are pure functions

**Testability challenges:**
- `create_google_auth()` reads environment variables directly — requires monkeypatching or env setup in tests
- `run_server()` / `run_with_restart()` run an infinite loop — would need thread management or mocking
- Live reload uses `os.kill()` with `signal.SIGINT` — affects the test process if not mocked
- File watcher uses `watchdog` observer — requires real filesystem or mock
- `FastMCP.as_proxy()` is an external dependency — would need mocking

## Recommended Test Structure

If tests are added, the recommended layout for this project:

```
mcp-proxy/
├── proxy_server.py
├── version.py
├── tests/
│   ├── __init__.py
│   ├── test_proxy_server.py       # Unit tests for ResilientMCPProxy
│   ├── test_config_handler.py     # Unit tests for ConfigFileHandler
│   ├── test_version.py            # Unit tests for version.py
│   └── fixtures/
│       └── mcp_config_test.json   # Minimal valid config for tests
└── pytest.ini                     # or pyproject.toml [tool.pytest]
```

## Recommended Test Framework

```
pytest>=7.0
pytest-mock          # For monkeypatching env vars and dependencies
pytest-asyncio       # If async FastMCP internals need testing
```

Add to `requirements-dev.txt`:
```
pytest>=7.0
pytest-mock
pytest-asyncio
```

## Recommended Test Patterns

**Unit testing config loading:**
```python
import pytest
from unittest.mock import patch
from proxy_server import ResilientMCPProxy

def test_load_config_success(tmp_path):
    config_file = tmp_path / "mcp_config.json"
    config_file.write_text('{"mcpServers": {"test": {"command": "npx", "args": []}}}')
    proxy = ResilientMCPProxy(str(config_file))
    assert proxy.load_config_with_retry() is True

def test_load_config_file_not_found():
    proxy = ResilientMCPProxy("nonexistent.json")
    assert proxy.load_config_with_retry() is False

def test_load_config_invalid_json(tmp_path):
    config_file = tmp_path / "mcp_config.json"
    config_file.write_text("NOT VALID JSON")
    proxy = ResilientMCPProxy(str(config_file))
    assert proxy.load_config_with_retry() is False
```

**Unit testing env var parsing:**
```python
from proxy_server import _parse_int_env

def test_parse_int_env_valid(monkeypatch):
    monkeypatch.setenv("MCP_PORT", "9090")
    assert _parse_int_env("MCP_PORT", 8080) == 9090

def test_parse_int_env_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("MCP_PORT", "not_a_number")
    assert _parse_int_env("MCP_PORT", 8080) == 8080

def test_parse_int_env_missing_uses_default():
    assert _parse_int_env("MCP_PORT_ABSENT", 8080) == 8080
```

**Unit testing Google auth factory:**
```python
def test_create_google_auth_missing_vars(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    from proxy_server import create_google_auth
    assert create_google_auth() is None

def test_create_google_auth_configured(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("MCP_BASE_URL", "https://example.com")
    from unittest.mock import patch
    with patch("proxy_server.GoogleProvider") as mock_provider:
        from proxy_server import create_google_auth
        result = create_google_auth()
        assert result is not None
```

**Unit testing version.py:**
```python
from version import get_version, get_version_info

def test_get_version_returns_string():
    v = get_version()
    assert isinstance(v, str)
    assert "+" in v  # semver build metadata format

def test_get_version_info_keys():
    info = get_version_info()
    assert set(info.keys()) == {"major", "minor", "patch", "build", "full"}
    assert isinstance(info["major"], int)
```

**Testing debounce logic in ConfigFileHandler:**
```python
from unittest.mock import MagicMock, patch
from proxy_server import ConfigFileHandler
import time

def test_debounced_reload_calls_callback(tmp_path):
    config = tmp_path / "config.json"
    config.touch()
    callback = MagicMock()
    handler = ConfigFileHandler(str(config), callback)
    handler._debounced_reload()
    time.sleep(1.2)  # Wait past debounce delay
    callback.assert_called_once()
```

## Key Test Priorities (if tests are added)

| Priority | Area | Rationale |
|----------|------|-----------|
| High | `load_config_with_retry()` | Core startup logic, retry/backoff paths |
| High | `_parse_int_env()` | Used for all numeric env vars |
| High | `create_google_auth()` — missing credentials | Auth failure path |
| Medium | `wait_for_port_available()` | Port binding logic |
| Medium | `ConfigFileHandler` debouncing | Reload trigger correctness |
| Medium | `get_version_info()` | Version parsing correctness |
| Low | `run_with_restart()` | Infinite loop — complex to test |

## Test Coverage Gap (Technical Debt)

The entire codebase has zero test coverage. This is the most significant quality concern. The following paths have no automated verification:

- Config validation failure paths
- Exponential backoff retry behavior
- Live reload debouncing
- Signal handler registration
- Server crash recovery loop
- Port availability polling

See `CONCERNS.md` for prioritized remediation approach.

---

*Testing analysis: 2026-05-30*
