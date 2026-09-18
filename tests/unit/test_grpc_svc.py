"""Tests backbone gRPC interne (Phase 2) — dispatch, contrat, capture intégrée au ledger."""

from __future__ import annotations

import pytest


@pytest.fixture
def internal_service():
    from grpc_svc.server import InternalService

    return InternalService()


@pytest.mark.asyncio
async def test_dispatch_process_capture_posts_ledger(internal_service):
    from payment.ledger import LEDGER

    before = len(LEDGER.posted_payments)
    result = await internal_service.dispatch(
        "ProcessCapture",
        {
            "payment_id": "grpc_test_1",
            "merchant_id": "merchant-api",
            "amount": 120.50,
            "currency": "EUR",
            "card_token": "tok_x",
            "three_ds_eci": "05",
            "three_ds_cavv": "AAABAAB",
        },
    )
    assert result["status"] == "approved"
    assert result["reason_code"] == "00"
    assert len(LEDGER.posted_payments) == before + 1


@pytest.mark.asyncio
async def test_dispatch_declines_zero_amount(internal_service):
    result = await internal_service.dispatch(
        "ProcessCapture",
        {"payment_id": "grpc_test_2", "amount": 0, "currency": "EUR"},
    )
    assert result["status"] == "declined"
    assert result["reason_code"] == "51"


@pytest.mark.asyncio
async def test_dispatch_evaluate_risk_with_injected_handler():
    from grpc_svc.server import InternalService

    async def risk_handler(req):
        return {"risk_score": 0.95, "recommendation": "decline", "challenge_required": False, "flags": ["test"]}

    svc = InternalService(risk=risk_handler)
    result = await svc.dispatch("EvaluateRisk", {"amount": 5000.0})
    assert result["recommendation"] == "decline"


@pytest.mark.asyncio
async def test_default_risk_hits_fraud_engine(internal_service):
    result = await internal_service.dispatch("EvaluateRisk", {"amount": 123.0, "currency": "EUR"})
    assert "risk_score" in result
    assert result["recommendation"] in ("approve", "review", "decline")


@pytest.mark.asyncio
async def test_inprocess_channel(internal_service):
    from grpc_svc.server import InProcessChannel

    chan = InProcessChannel(internal_service)
    result = await chan.invoke("EvaluateRisk", {"amount": 10.0, "currency": "EUR"})
    assert "risk_score" in result


def test_unknown_method_raises(internal_service):
    import asyncio

    with pytest.raises(ValueError):
        asyncio.run(internal_service.dispatch("UnknownMethod", {}))