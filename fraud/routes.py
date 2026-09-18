"""Fraud detection routes."""

from fastapi import APIRouter, Depends

from config import get_settings
from fraud.engine import FraudEngine
from fraud.schemas import FraudCheckRequest, FraudCheckResponse
from shared.auth import TokenClaims, verify_token
from shared.events import emit_event
from shared.metrics import FRAUD_SCORE

router = APIRouter()
settings = get_settings()
fraud_engine = FraudEngine(model_path=settings.FRAUD_MODEL_PATH)


@router.post("/check", response_model=FraudCheckResponse)
async def check_fraud(
    data: FraudCheckRequest,
    claims: TokenClaims = Depends(verify_token),
):
    result = fraud_engine.analyze(
        amount=data.amount,
        currency=data.currency,
        card_token=data.card_token,
        merchant_id=data.merchant_id or claims.merchant_id,
        ip_address=data.ip_address,
    )
    FRAUD_SCORE.observe(result["risk_score"])
    emit_event(
        {
            "event_type": "fraud_score",
            "merchant_id": data.merchant_id,
            "amount": data.amount,
            "risk_score": result["risk_score"],
            "risk_level": result["risk_level"],
            "recommendation": result["recommendation"],
            "flags": result["flags"],
            "source_ip": data.ip_address,
            "scenario": "fraud_spike" if result["risk_score"] >= 0.85 else "fraud_check",
        }
    )
    return FraudCheckResponse(**result)
