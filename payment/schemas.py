"""Payment schemas."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class PaymentStatus(str, Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"
    FRAUD_REVIEW = "fraud_review"
    CHALLENGE_REQUIRED = "challenge_required"


class ProcessPaymentRequest(BaseModel):
    amount: float = Field(..., gt=0)
    currency: str = Field(default="EUR")
    card_token: str = Field(..., description="Token de la carte (pas le PAN réel)")
    merchant_id: str
    description: str = ""
    ip_address: str = ""
    fraud_score: float | None = None
    fraud_flags: list[str] = Field(default_factory=list)
    card_last_four: str = "****"
    card_brand: str = "unknown"
    correlation_id: str = ""
    three_ds_status: str | None = None
    three_ds_eci: str | None = None
    three_ds_cavv: str | None = None
    idempotency_key: str | None = Field(default=None, max_length=64)


class ProcessPaymentResponse(BaseModel):
    id: str
    status: PaymentStatus
    amount: float
    currency: str
    card_last_four: str
    merchant_id: str
    authorization_code: str | None = None
    created_at: datetime
    fraud_score: float | None = None
    correlation_id: str | None = None
    idempotent_replay: bool = False
    three_ds_status: str | None = None
    three_ds_eci: str | None = None
