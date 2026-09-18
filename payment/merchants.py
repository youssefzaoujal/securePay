"""Onboarding merchant — client OAuth2 + webhook HMAC."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl

from shared.auth import TokenClaims, require_role, verify_token

router = APIRouter()

_MERCHANTS: dict[str, dict] = {
    "merchant-api": {
        "id": "merchant-api",
        "legal_name": "Demo Merchant SAS",
        "webhook_url": "http://localhost:9000/webhooks/securepay",
        "status": "active",
        "mcc": "5411",
        "oauth_client_id": "merchant-api",
        "created_at": datetime.now(timezone.utc),
    }
}


class MerchantCreate(BaseModel):
    id: str = Field(..., min_length=3, max_length=64)
    legal_name: str
    webhook_url: HttpUrl | None = None
    mcc: str = Field(default="5999", min_length=4, max_length=4)


class MerchantOut(BaseModel):
    id: str
    legal_name: str
    webhook_url: str | None
    status: str
    mcc: str | None
    oauth_client_id: str | None


@router.post("", response_model=MerchantOut, status_code=status.HTTP_201_CREATED)
async def onboard_merchant(
    payload: MerchantCreate,
    claims: TokenClaims = Depends(require_role("admin")),
):
    if payload.id in _MERCHANTS:
        raise HTTPException(status_code=409, detail="Merchant déjà onboardé")
    row = {
        "id": payload.id,
        "legal_name": payload.legal_name,
        "webhook_url": str(payload.webhook_url) if payload.webhook_url else None,
        "status": "active",
        "mcc": payload.mcc,
        "oauth_client_id": payload.id,
        "created_at": datetime.now(timezone.utc),
    }
    _MERCHANTS[payload.id] = row
    return MerchantOut(**row)


@router.get("/me", response_model=MerchantOut)
async def my_merchant(claims: TokenClaims = Depends(verify_token)):
    row = _MERCHANTS.get(claims.merchant_id)
    if not row:
        raise HTTPException(status_code=404, detail="Merchant inconnu")
    return MerchantOut(**row)
