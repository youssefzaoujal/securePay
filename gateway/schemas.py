"""Gateway schemas."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Currency(str, Enum):
    EUR = "EUR"
    USD = "USD"
    GBP = "GBP"
    MAD = "MAD"


class PaymentStatus(str, Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"
    FRAUD_REJECTED = "fraud_rejected"
    CHALLENGE_REQUIRED = "challenge_required"


class PaymentRequest(BaseModel):
    amount: float = Field(..., gt=0, description="Montant en devise")
    currency: Currency = Field(default=Currency.EUR)
    card_number: str = Field(..., min_length=13, max_length=19)
    card_expiry: str = Field(..., pattern=r"^\d{2}/\d{2}$")
    card_cvv: str = Field(..., min_length=3, max_length=4)
    merchant_id: str | None = None
    description: str = ""


class PaymentResponse(BaseModel):
    id: str
    status: PaymentStatus
    amount: float
    currency: str
    merchant_id: str
    created_at: datetime


class TokenizeRequest(BaseModel):
    card_number: str = Field(..., min_length=13, max_length=19)
    card_expiry: str = Field(..., pattern=r"^\d{2}/\d{2}$")
    card_cvv: str = Field(..., min_length=3, max_length=4)


class TokenizeResponse(BaseModel):
    token: str
    last_four: str
    card_brand: str
    expires_at: str
    algorithm: str = "AES-256-GCM"
    cvv_stored: bool = False


class FraudCheckRequest(BaseModel):
    amount: float
    currency: Currency
    card_token: str
    merchant_id: str
    ip_address: str = ""


class FraudCheckResponse(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_level: str
    flags: list[str]
    recommendation: str
    challenge_required: bool = False
