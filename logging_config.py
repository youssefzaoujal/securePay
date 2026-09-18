"""Logging structuré JSON pour SecurePay - PCI-DSS Req 10 + rédaction PAN."""

import logging
import uuid
from contextvars import ContextVar

import structlog

from shared.redaction import redact_secrets

correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def generate_correlation_id() -> str:
    cid = f"corr_{uuid.uuid4().hex[:12]}"
    correlation_id.set(cid)
    return cid


def _redact_processor(_logger, _method, event_dict):
    return redact_secrets(event_dict)


def _correlation_processor(_logger, _method, event_dict):
    event_dict["correlation_id"] = correlation_id.get("")
    event_dict.setdefault("service", "securepay")
    return event_dict


def configure_logging(log_level: str = "INFO", json_output: bool = True):
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _correlation_processor,
        _redact_processor,
        structlog.processors.StackInfoRenderer(),
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer(default=str))
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str):
    return structlog.get_logger(name)
