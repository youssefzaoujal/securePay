"""Middleware commun : correlation-id, métriques, sécurité headers."""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from logging_config import correlation_id, configure_logging
from shared.metrics import REQUEST_LATENCY, metrics_response
from shared.tracing import span


class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cid = request.headers.get("x-correlation-id") or f"corr_{uuid.uuid4().hex[:12]}"
        correlation_id.set(cid)
        start = time.perf_counter()
        with span("http.request", service=request.app.title, route=request.url.path, method=request.method):
            response = await call_next(request)
        elapsed = time.perf_counter() - start
        route = request.url.path
        REQUEST_LATENCY.labels(
            service=request.app.title,
            route=route,
            method=request.method,
        ).observe(elapsed)
        response.headers["X-Correlation-ID"] = cid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response


def mount_security(app: FastAPI) -> None:
    configure_logging()
    app.add_middleware(CorrelationMiddleware)

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        body, content_type = metrics_response()
        return Response(content=body, media_type=content_type)
