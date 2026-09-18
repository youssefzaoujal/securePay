"""Tokenization schemas."""

from pydantic import BaseModel, Field


class TokenizeRequest(BaseModel):
    card_number: str = Field(..., min_length=13, max_length=19, description="PAN de test")
    card_expiry: str = Field(..., pattern=r"^\d{2}/\d{2}$", description="MM/YY")
    card_cvv: str = Field(..., min_length=3, max_length=4, description="CVV — jamais persisté")


class TokenizeResponse(BaseModel):
    token: str
    last_four: str
    card_brand: str
    expires_at: str
    algorithm: str = "AES-256-GCM"
    cvv_stored: bool = False


class DetokenizeRequest(BaseModel):
    token: str
