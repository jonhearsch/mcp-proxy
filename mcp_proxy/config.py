"""Configuration loading for MCP Proxy."""

import os
import json
import re
import time
import logging
from pathlib import Path
from typing import Optional

import jsonschema


_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigEnvVarError(Exception):
    """A config value references an environment variable that isn't set."""

    def __init__(self, var_name: str):
        self.var_name = var_name
        super().__init__(f"Environment variable '{var_name}' referenced in config is not set")


def _expand_env_vars(obj):
    """
    Recursively substitute ${VAR_NAME} references in string values from
    os.environ. Raises ConfigEnvVarError if a referenced variable is unset --
    silently leaving the literal placeholder in place (e.g. in a server's
    args/env) would be a worse failure mode than a loud startup error.
    """
    if isinstance(obj, dict):
        return {key: _expand_env_vars(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    if isinstance(obj, str):
        def _replace(match: "re.Match[str]") -> str:
            var_name = match.group(1)
            if var_name not in os.environ:
                raise ConfigEnvVarError(var_name)
            return os.environ[var_name]

        return _ENV_VAR_PATTERN.sub(_replace, obj)
    return obj


def _normalize_header_keys(config: dict) -> dict:
    """
    Lowercase per-server HTTP header keys.

    fastmcp merges inbound client headers (keyed lowercase, e.g. "authorization")
    with configured per-server headers via a plain dict union. If the configured
    key differs only in case (e.g. "Authorization"), both survive as separate
    dict entries and the outbound request ends up with two Authorization header
    lines -- upstream servers may honor the wrong one (the forwarded inbound
    header) instead of the configured value. Normalizing to lowercase here makes
    the union correctly overwrite the inbound header with the configured one.
    """
    for server in config.get("mcpServers", {}).values():
        headers = server.get("headers")
        if isinstance(headers, dict):
            server["headers"] = {k.lower(): v for k, v in headers.items()}
    return config


def _parse_int_env(name: str, default: int) -> int:
    """Parse an integer environment variable with a friendly fallback on invalid input."""
    val = os.getenv(name, str(default))
    try:
        return int(val)
    except ValueError:
        logging.getLogger(__name__).warning(
            f"Invalid value for {name}='{val}', using default {default}"
        )
        return default


_TRUTHY_VALUES = ("true", "1", "yes")
_FALSY_VALUES = ("false", "0", "no", "")


def _parse_bool_env(name: str, default: bool = False) -> bool:
    """
    Parse a boolean environment variable.

    Accepts "true"/"1"/"yes" as True and "false"/"0"/"no"/"" as False
    (case-insensitive). Unrecognized values log a warning and fall back
    to the default rather than being silently treated as False.
    """
    raw = os.getenv(name)
    if raw is None:
        return default

    val = raw.strip().lower()
    if val in _TRUTHY_VALUES:
        return True
    if val in _FALSY_VALUES:
        return False

    logging.getLogger(__name__).warning(
        f"Invalid value for {name}='{raw}', using default {default}"
    )
    return default


def load_config_with_retry(
    config_path: str, max_retries: int, logger: logging.Logger
) -> tuple[bool, Optional[dict]]:
    """
    Load and validate the MCP configuration with retry logic, including JSON schema validation.

    Implements exponential backoff retry strategy for transient errors
    while immediately failing for permanent errors like file not found or
    schema validation errors.

    Args:
        config_path: Path to the JSON configuration file
        max_retries: Maximum number of retry attempts
        logger: Logger instance for output

    Returns:
        tuple[bool, Optional[dict]]: (success, config) where config is None on failure
    """
    # Schema is at the project root — two levels up from this module file
    schema_path = str(Path(__file__).parent.parent / "mcp_config.schema.json")

    logger.info(f"Loading configuration from: {os.path.abspath(config_path)}")

    try:
        with open(schema_path, "r") as sf:
            schema = json.load(sf)
        logger.info(f"✓ Loaded schema from: {schema_path}")
    except Exception as e:
        logger.error(f"✗ Failed to load config schema from {schema_path}: {e}")
        return False, None

    for attempt in range(max_retries):
        try:
            abs_config_path = os.path.abspath(config_path)
            logger.info(
                f"Attempting to load config from {abs_config_path} "
                f"(attempt {attempt + 1}/{max_retries})"
            )

            with open(config_path, "r") as f:
                config = json.load(f)
            logger.info(f"✓ Loaded config file from {abs_config_path}")

            config = _expand_env_vars(config)
            config = _normalize_header_keys(config)

            jsonschema.validate(instance=config, schema=schema)

            server_count = len(config["mcpServers"])
            logger.info(
                f"✓ Successfully loaded and validated configuration with {server_count} servers"
            )
            return True, config

        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            return False, None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return False, None
        except ConfigEnvVarError as e:
            logger.error(f"Config load failed: {e}")
            return False, None
        except jsonschema.ValidationError as e:
            logger.error(f"Config schema validation failed: {e.message}")
            return False, None
        except Exception as e:
            logger.error(f"Config load attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                backoff_time = 2 ** attempt
                logger.info(f"Retrying in {backoff_time} seconds...")
                time.sleep(backoff_time)
            else:
                logger.error("Failed to load config after all retries")

    return False, None
