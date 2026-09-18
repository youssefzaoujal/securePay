"""Fraud schemas."""

from pydantic import BaseModel, Field


class FraudCheckRequest(BaseModel):
    amount: float = Field(..., gt=0)
    currency: str
    card_token: str
    merchant_id: str
    ip_address: str = ""


class FraudCheckResponse(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str
    flags: list[str] = Field(default_factory=list)
    recommendation: str
    challenge_required: bool = False
