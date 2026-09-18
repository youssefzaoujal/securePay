"""Gateway proxy — forward interne avec correlation-id."""

import httpx
from fastapi import HTTPException, status

from logging_config import correlation_id

SERVICE_TIMEOUT = 10.0


async def proxy_to_service(
    service_url: str,
    path: str,
    method: str = "GET",
    data: dict | None = None,
    token: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict:
    headers = {"X-Correlation-ID": correlation_id.get("")}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update({k: v for k, v in extra_headers.items() if v})

    # W3C traceparent : corrélation logs/métriques/traces bout-en-bout.
    from shared.tracing import traceparent_header

    traceparent = traceparent_header()
    if traceparent:
        headers["traceparent"] = traceparent

    url = f"{service_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(timeout=SERVICE_TIMEOUT) as client:
        try:
            response = await client.request(method.upper(), url, json=data, headers=headers)
            if response.status_code >= 400:
                detail: object
                try:
                    detail = response.json()
                except Exception:
                    detail = response.text
                raise HTTPException(status_code=response.status_code, detail=detail)
            if response.status_code == 204 or not response.content:
                return {}
            return response.json()
        except HTTPException:
            raise
        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=f"Service {service_url} indisponible (timeout)",
            ) from exc
        except httpx.ConnectError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Service {service_url} inaccessible (fail-secure: capture refusée)",
            ) from exc
