"""Structured logging configuration for the AI Assurance Framework.

Call ``configure_logging()`` once at startup (the CLI does this).  Use
``get_logger(__name__)`` everywhere else.
"""
import json
import logging
import time
from typing import Any


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not root.handlers:
        handler = logging.StreamHandler()
        root.addHandler(handler)
    for handler in root.handlers:
        handler.setFormatter(_JsonFormatter() if fmt == "json" else logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        extra_skip = {
            "args", "created", "exc_info", "exc_text", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs", "message",
            "msg", "name", "pathname", "process", "processName", "relativeCreated",
            "stack_info", "thread", "threadName",
        }
        for key, val in record.__dict__.items():
            if key not in extra_skip:
                payload[key] = val
        return json.dumps(payload)
