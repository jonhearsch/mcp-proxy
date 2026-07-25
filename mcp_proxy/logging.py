"""
Structured JSON logging for MCP Proxy using structlog.

Provides configure_logging() and get_logger() as the public API.
All log output — including from fastmcp, httpx, and watchdog via the
stdlib bridge — is written as JSON to stdout.
"""

import sys
import logging
import structlog


def configure_logging(log_level_str: str = "INFO", per_logger_str: str = "") -> None:
    """
    Configure structlog JSON pipeline with stdlib bridge.

    Sets up structured JSON logging so every line written to stdout is
    a valid JSON object. Stdlib loggers (fastmcp, httpx, watchdog) are
    captured via ProcessorFormatter and also emitted as JSON.

    Args:
        log_level_str: Global log level string (e.g. "INFO", "DEBUG").
        per_logger_str: Comma-separated "name:LEVEL" overrides
                        (same format as MCP_LOG_LEVELS env var).
    """
    shared_processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    structlog.configure(
        processors=shared_processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    level = getattr(logging, log_level_str.upper(), logging.INFO)
    root_logger.setLevel(level)

    # Apply per-logger level overrides
    if per_logger_str:
        for entry in per_logger_str.split(","):
            entry = entry.strip()
            if ":" not in entry:
                continue
            name, lvl_str = entry.split(":", 1)
            name = name.strip()
            lvl_str = lvl_str.strip().upper()
            try:
                lvl = getattr(logging, lvl_str)
                logging.getLogger(name).setLevel(lvl)
            except AttributeError:
                # Can't log here — logging may not be fully ready; silently skip
                pass

    # Cap noisy libraries at INFO unless already overridden
    logging.getLogger("fastmcp").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.INFO)

    # Optional auth debug mode
    from mcp_proxy.config import _parse_bool_env

    if _parse_bool_env("MCP_AUTH_DEBUG"):
        logging.getLogger("fastmcp.auth").setLevel(logging.DEBUG)
        logging.getLogger("fastmcp.server.auth").setLevel(logging.DEBUG)


def get_logger(name: str = None) -> structlog.stdlib.BoundLogger:
    """
    Return a structlog BoundLogger for the given name.

    Usage:
        from mcp_proxy.logging import get_logger
        logger = get_logger(__name__)
        logger.info("something happened", key="value")
    """
    return structlog.get_logger(name)
