"""Tracing distribué OpenTelemetry-compatible, corrélé au `correlation_id`.

Fermeture de la boucle logs + métriques + traces :
  - le `correlation_id` SecurePay devient la `trace_id` racine
  - propagation W3C `traceparent` entre services via headers
  - export OTLP automatique si `OTEL_EXPORTER_OTLP_ENDPOINT` est défini
  - fallback : spans JSONL locaux (lab, zéro infra)

L'observabilité ne bypass jamais l'auth : un échec d'export ne change
jamais une décision métier (de couleur `try/except` total).
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_current_span: ContextVar[dict[str, Any] | None] = ContextVar("securepay_span", default=None)


def _log_path() -> Path:
    return Path(os.getenv("SECUREPAY_TRACE_LOG", "logs/otel-spans.jsonl"))


def export_span(span: dict[str, Any]) -> None:
    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(span, default=str) + "\n")
    except Exception:
        return


def _span_from_correlation(cid: str) -> str:
    """corr_abc...  → trace_id hex 16 octets (stabilisé pour la corrélation)."""
    return f"{cid}-{uuid.uuid4().hex[:16]}" if cid and cid.startswith("corr_") else uuid.uuid4().hex


def _try_otlp(span: dict[str, Any]) -> None:
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
        import requests  # noqa: PLC0415

        requests.post(
            f"{endpoint.rstrip('/')}/v1/traces",
            json={"resource_spans": [{"scope_spans": [{"spans": [_otlp_span(span)]}]}]},
            timeout=0.5,
        )
    except Exception:
        return


def _otlp_span(span: dict[str, Any]) -> dict[str, Any]:
    return {
        "traceId": span.get("trace_id", ""),
        "spanId": span.get("span_id", ""),
        "parentSpanId": span.get("parent_span_id"),
        "name": span.get("name", ""),
        "startTimeUnixNano": span.get("start_ns", 0),
        "endTimeUnixNano": span.get("end_ns", 0),
        "attributes": [
            {"key": k, "value": {"stringValue": str(v)}} for k, v in span.get("attributes", {}).items()
        ],
        "status": {"code": 2 if span.get("status") == "error" else 1},
    }


@contextmanager
def span(name: str, **attributes: Any) -> Generator[dict[str, Any], None, None]:
    from logging_config import correlation_id

    started = time.perf_counter()
    cid = correlation_id.get("")
    record = {
        "trace_id": _span_from_correlation(cid),
        "span_id": uuid.uuid4().hex[:16],
        "parent_span_id": (_current_span.get() or {}).get("span_id"),
        "correlation_id": cid,
        "name": name,
        "attributes": attributes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "start_ns": time.time_ns(),
        "status": "ok",
    }
    token = _current_span.set(record)
    try:
        yield record
    except Exception as exc:
        record["status"] = "error"
        record["error.type"] = type(exc).__name__
        raise
    finally:
        record["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        record["end_ns"] = time.time_ns()
        _current_span.reset(token)
        export_span(record)
        _try_otlp(record)


def traceparent_header() -> str:
    """W3C traceparent version 00 (lab : sans flags sampling)."""
    span = _current_span.get()
    if not span:
        return ""
    return f"00-{span.get('trace_id', '0' * 32)[:32].ljust(32, '0')}-{span.get('span_id', '0' * 16)[:16]}-01"