"""Tests d'intégration - API Gateway."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from gateway.main import app


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_endpoint(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "SecurePay"


class TestPaymentFlow:
    @pytest.mark.asyncio
    async def test_create_payment_requires_auth(self, client):
        response = await client.post(
            "/api/v1/payments",
            json={
                "amount": 100.0,
                "currency": "EUR",
                "card_number": "4111111111111111",
                "card_expiry": "12/25",
                "card_cvv": "123",
                "merchant_id": "MERCH_001",
            },
        )
        # Sans token, doit retourner 403
        assert response.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_tokenize_requires_auth(self, client):
        response = await client.post(
            "/api/v1/tokens",
            json={
                "card_number": "4111111111111111",
                "card_expiry": "12/25",
                "card_cvv": "123",
            },
        )
        assert response.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_fraud_check_requires_auth(self, client):
        response = await client.post(
            "/api/v1/fraud/check",
            json={
                "amount": 100.0,
                "currency": "EUR",
                "card_token": "tok_test",
                "merchant_id": "MERCH_001",
            },
        )
        assert response.status_code in (401, 403)
