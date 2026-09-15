from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class JsonFormatter(logging.Formatter):
    """Format log records as JSON Lines."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(
                record,
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if hasattr(record, "event"):
            payload["event"] = record.event

        return json.dumps(
            payload,
            ensure_ascii=False,
            default=str,
        )


def create_logger(
    name: str = "windows_monitoring_agent",
    log_directory: str | Path = "logs",
) -> logging.Logger:
    """
    Create the application logger.

    Logs are written to:
        logs/monitoring.jsonl
    """

    log_path = Path(log_directory)
    log_path.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Prevent duplicate handlers when the logger is initialized twice.
    if logger.handlers:
        return logger

    formatter = JsonFormatter()

    file_handler = RotatingFileHandler(
        log_path / "monitoring.jsonl",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )

    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    console_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s"
    )

    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def log_event(
    logger: logging.Logger,
    level: int,
    message: str,
    event: dict[str, Any],
) -> None:
    """Write a structured security event."""

    logger.log(
        level,
        message,
        extra={"event": event},
    )