"""3DS2 schemas."""

from pydantic import BaseModel, Field


class ChallengeRequest(BaseModel):
    transaction_id: str = Field(..., description="ID de la transaction à challenger")
    method: str = Field(default="sms", description="sms ou email")
    phone_number: str = Field(default="", description="Numéro de téléphone (pour SMS)")
    email: str = Field(default="", description="Email (pour email)")


class ChallengeVerifyRequest(BaseModel):
    challenge_id: str = Field(..., description="ID du challenge")
    otp_code: str = Field(..., min_length=6, max_length=6, description="Code OTP à 6 chiffres")


class ChallengeResponse(BaseModel):
    challenge_id: str
    status: str
    method: str
    message: str
