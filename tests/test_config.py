"""Tests for mcp_proxy.config: env var parsing, config loading, and ${VAR} expansion."""

import json
import logging

import pytest

from mcp_proxy.config import (
    ConfigEnvVarError,
    _expand_env_vars,
    _normalize_header_keys,
    _parse_bool_env,
    _parse_int_env,
    load_config_with_retry,
)


@pytest.fixture
def logger():
    return logging.getLogger("test")


# --- _parse_int_env ---------------------------------------------------


def test_parse_int_env_valid(monkeypatch):
    monkeypatch.setenv("MCP_TEST_PORT", "9090")
    assert _parse_int_env("MCP_TEST_PORT", 8080) == 9090


def test_parse_int_env_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("MCP_TEST_PORT", "not_a_number")
    assert _parse_int_env("MCP_TEST_PORT", 8080) == 8080


def test_parse_int_env_missing_uses_default(monkeypatch):
    monkeypatch.delenv("MCP_TEST_PORT_ABSENT", raising=False)
    assert _parse_int_env("MCP_TEST_PORT_ABSENT", 8080) == 8080


# --- _parse_bool_env ----------------------------------------------------


@pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "Yes"])
def test_parse_bool_env_truthy(monkeypatch, raw):
    monkeypatch.setenv("MCP_TEST_FLAG", raw)
    assert _parse_bool_env("MCP_TEST_FLAG") is True


@pytest.mark.parametrize("raw", ["false", "FALSE", "0", "no", ""])
def test_parse_bool_env_falsy(monkeypatch, raw):
    monkeypatch.setenv("MCP_TEST_FLAG", raw)
    assert _parse_bool_env("MCP_TEST_FLAG", default=True) is False


def test_parse_bool_env_missing_uses_default(monkeypatch):
    monkeypatch.delenv("MCP_TEST_FLAG_ABSENT", raising=False)
    assert _parse_bool_env("MCP_TEST_FLAG_ABSENT", default=True) is True


def test_parse_bool_env_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("MCP_TEST_FLAG", "maybe")
    assert _parse_bool_env("MCP_TEST_FLAG", default=True) is True


# --- _expand_env_vars -----------------------------------------------------


def test_expand_env_vars_substitutes(monkeypatch):
    monkeypatch.setenv("TEST_API_KEY", "secret123")
    config = {"mcpServers": {"srv": {"args": ["--key=${TEST_API_KEY}"]}}}
    result = _expand_env_vars(config)
    assert result["mcpServers"]["srv"]["args"] == ["--key=secret123"]


def test_expand_env_vars_leaves_plain_strings_untouched():
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["pkg"]}}}
    assert _expand_env_vars(config) == config


def test_expand_env_vars_missing_var_raises(monkeypatch):
    monkeypatch.delenv("TEST_MISSING_VAR", raising=False)
    with pytest.raises(ConfigEnvVarError):
        _expand_env_vars({"env": {"KEY": "${TEST_MISSING_VAR}"}})


# --- _normalize_header_keys ------------------------------------------------


def test_normalize_header_keys_lowercases_authorization():
    config = {
        "mcpServers": {"context7": {"headers": {"Authorization": "Bearer ctx7sk-x"}}}
    }
    result = _normalize_header_keys(config)
    assert result["mcpServers"]["context7"]["headers"] == {
        "authorization": "Bearer ctx7sk-x"
    }


def test_normalize_header_keys_leaves_servers_without_headers_untouched():
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["pkg"]}}}
    assert _normalize_header_keys(config) == config


def test_normalize_header_keys_handles_multiple_servers():
    config = {
        "mcpServers": {
            "a": {"headers": {"X-Api-Key": "a-key"}},
            "b": {"headers": {"Authorization": "Bearer b-key"}},
        }
    }
    result = _normalize_header_keys(config)
    assert result["mcpServers"]["a"]["headers"] == {"x-api-key": "a-key"}
    assert result["mcpServers"]["b"]["headers"] == {"authorization": "Bearer b-key"}


# --- load_config_with_retry -----------------------------------------------


def _write_config(path, data):
    path.write_text(json.dumps(data))
    return str(path)


def test_load_config_success(tmp_path, logger):
    config_path = _write_config(
        tmp_path / "mcp_config.json",
        {"mcpServers": {"test": {"command": "npx", "args": ["pkg"]}}},
    )
    success, config = load_config_with_retry(config_path, max_retries=3, logger=logger)
    assert success is True
    assert "test" in config["mcpServers"]


def test_load_config_file_not_found(tmp_path, logger):
    success, config = load_config_with_retry(
        str(tmp_path / "nonexistent.json"), max_retries=3, logger=logger
    )
    assert success is False
    assert config is None


def test_load_config_invalid_json(tmp_path, logger):
    config_path = tmp_path / "mcp_config.json"
    config_path.write_text("NOT VALID JSON")
    success, config = load_config_with_retry(str(config_path), max_retries=3, logger=logger)
    assert success is False
    assert config is None


def test_load_config_expands_env_vars(tmp_path, logger, monkeypatch):
    monkeypatch.setenv("TEST_API_KEY", "secret123")
    config_path = _write_config(
        tmp_path / "mcp_config.json",
        {"mcpServers": {"test": {"command": "npx", "args": ["--key=${TEST_API_KEY}"]}}},
    )
    success, config = load_config_with_retry(config_path, max_retries=3, logger=logger)
    assert success is True
    assert config["mcpServers"]["test"]["args"] == ["--key=secret123"]


def test_load_config_normalizes_header_keys(tmp_path, logger):
    config_path = _write_config(
        tmp_path / "mcp_config.json",
        {
            "mcpServers": {
                "context7": {
                    "url": "https://mcp.context7.com/mcp",
                    "transport": "http",
                    "headers": {"Authorization": "Bearer ctx7sk-x"},
                }
            }
        },
    )
    success, config = load_config_with_retry(config_path, max_retries=3, logger=logger)
    assert success is True
    assert config["mcpServers"]["context7"]["headers"] == {
        "authorization": "Bearer ctx7sk-x"
    }


def test_load_config_missing_env_var_fails_without_retry(tmp_path, logger, monkeypatch):
    monkeypatch.delenv("TEST_MISSING_VAR", raising=False)
    config_path = _write_config(
        tmp_path / "mcp_config.json",
        {"mcpServers": {"test": {"command": "npx", "args": ["--key=${TEST_MISSING_VAR}"]}}},
    )
    success, config = load_config_with_retry(config_path, max_retries=3, logger=logger)
    assert success is False
    assert config is None
