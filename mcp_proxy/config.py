"""Configuration loading for MCP Proxy."""

import os
import json
import time
import logging
from pathlib import Path
from typing import Optional

import jsonschema


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
