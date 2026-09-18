"""Fail-secure : JWKS / services down → refuse, jamais skip auth. Tracing n'ouvre pas le flux."""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from gateway.proxy import proxy_to_service
from shared.auth import verify_token
from shared.tracing import span


@pytest.mark.asyncio
async def test_jwks_outage_is_401_not_anonymous(monkeypatch):
    async def down():
        raise ConnectionError("keycloak down")

    monkeypatch.setattr("shared.auth._fetch_jwks", down)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="aaa.bbb.ccc")
    with pytest.raises(HTTPException) as exc:
        await verify_token(creds)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_downstream_connect_error_is_503_fail_secure(monkeypatch):
    class BoomClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def request(self, *_a, **_k):
            import httpx

            raise httpx.ConnectError("fraud down")

    monkeypatch.setattr("gateway.proxy.httpx.AsyncClient", BoomClient)
    with pytest.raises(HTTPException) as exc:
        await proxy_to_service("http://fraud:8003", "/api/v1/check", "POST", {"amount": 1})
    assert exc.value.status_code == 503
    assert "fail-secure" in str(exc.value.detail).lower()


@pytest.mark.asyncio
async def test_fraud_timeout_never_silently_approves(monkeypatch):
    """Panne injectée sur le moteur de fraude → 504 (fail-closed), jamais 201 approve.

    Résilience testée : en cas de timeout/inaccessibilité du service fraude,
    la capture est REFUSÉE — le système ne dégrade jamais vers un approve silencieux.
    """
    class TimeoutClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc):
            return None

        async def request(self, *_a, **_k):
            import httpx

            raise httpx.TimeoutException("fraud timed out after 10s")

    monkeypatch.setattr("gateway.proxy.httpx.AsyncClient", TimeoutClient)
    with pytest.raises(HTTPException) as exc:
        await proxy_to_service("http://fraud:8003", "/api/v1/check", "POST", {"amount": 250.0})
    assert exc.value.status_code == 504
    assert "indisponible" in str(exc.value.detail).lower()


@pytest.mark.asyncio
async def test_fraud_down_blocks_full_gateway_payment(monkeypatch):
    """Bout-en-bout : failure de `POST /api/v1/payments` quand fraud est DOWN."""
    from fastapi import HTTPException as FE

    calls: list[str] = []

    async def fraud_down(*_a, **_k):
        calls.append("fraud")
        raise FE(status_code=503, detail="Service http://fraud:8003 inaccessible (fail-secure)")

    async def fake_proxy_service(service_url, path, method, data, token, extra_headers=None):
        if path.startswith("/api/v1/check"):  # le check fraude (FRAUD_SERVICE_URL=localhost)
            return await fraud_down()
        return {"token": "tok_test", "last_four": "1111", "card_brand": "visa"}

    monkeypatch.setattr("gateway.routes.proxy_to_service", fake_proxy_service)
    from fastapi import Request
    from starlette.datastructures import Headers

    class FakeClaims(dict):
        @property
        def merchant_id(self):
            return "merchant-api"

        @property
        def roles(self):
            return ["merchant"]

        @property
        def subject(self):
            return "merchant-api"

    request = Request({"type": "http", "method": "POST", "path": "/api/v1/payments", "headers": Headers(), "client": ("127.0.0.1", 5000)})
    # Premier appel (tokenize) passe ; l'appel fraud lève 503 propagé.
    from gateway.routes import create_payment

    with pytest.raises(FE) as exc:
        await create_payment(
            payment=type(
                "P",
                (),
                {
                    "amount": 250.0,
                    "currency": type("C", (), {"value": "EUR"})(),
                    "card_number": "4111111111111111",
                    "card_expiry": "12/29",
                    "card_cvv": "123",
                    "merchant_id": "merchant-api",
                    "description": "test",
                },
            )(),
            request=request,
            claims=FakeClaims(),
        )
    assert exc.value.status_code == 503
    assert calls, "le gateway doit avoir tenté le score fraude avant autorisation"


def test_tracing_does_not_swallow_security_errors():
    with pytest.raises(PermissionError):
        with span("auth.verify"):
            raise PermissionError("denied")
