"""structlog JSON logging with secret redaction."""
from __future__ import annotations

import enum
import logging
import re
import sys
import uuid
from datetime import date, datetime
from typing import Any

import structlog

from app.core.context import correlation_id_var

MASK = "[REDACTED]"
PEM_MASK = "[REDACTED PEM]"
_SENSITIVE_KEY = re.compile(
    r"(password|passwd|passphrase|private[_-]?key|secret|token|authorization|cookie|api[_-]?key|credential_pem|csrf)",
    re.IGNORECASE,
)
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|$)", re.DOTALL)
_MAX_DEPTH = 12


def redact_string(value: str) -> str:
    if "-----BEGIN" in value:
        return _PEM_BLOCK.sub(PEM_MASK, value)
    return value


def redact(obj: Any, _depth: int = 0) -> Any:
    """Return a deep copy of ``obj`` with sensitive keys masked and PEM blocks removed."""
    if _depth > _MAX_DEPTH:
        return MASK
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SENSITIVE_KEY.search(k) and v is not None and not isinstance(v, bool):
                out[k] = MASK
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(obj, (list, tuple, set)):
        return [redact(v, _depth + 1) for v in obj]
    if isinstance(obj, str):
        return redact_string(obj)
    if isinstance(obj, (bytes, bytearray)):
        return "[BINARY]"
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, enum.Enum):
        return redact(obj.value, _depth + 1)
    return obj


def redaction_processor(_logger, _name, event_dict: dict) -> dict:
    return redact(event_dict)


def _add_correlation(_logger, _name, event_dict: dict) -> dict:
    cid = correlation_id_var.get()
    if cid and "correlation_id" not in event_dict:
        event_dict["correlation_id"] = cid
    return event_dict


def configure_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=lvl, format="%(message)s", force=True)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _add_correlation,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            redaction_processor,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(lvl),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str | None = None):
    return structlog.get_logger(name)
