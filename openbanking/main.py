"""API Open Banking PSD2 — consentements AISP/PISP (Phase 3)."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from config import get_settings
from openbanking.service import OpenBankingService, SERVICE, ROLE_AISP, ROLE_PISP
from shared.http import mount_security

settings = get_settings()


class ConsentRequest(BaseModel):
    role: str
    tpp_name: str
    account_ids: list[str] = []
    amount_limit: float | None = None


class AuthorizeRequest(BaseModel):
    consent_id: str
    approve: bool = True
    otp: str = "123456"


class TokenRequest(BaseModel):
    consent_id: str
    authorization_code: str


class InitiationRequest(BaseModel):
    consent_id: str
    access_token: str
    amount: float
    currency: str = "EUR"


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="SecurePay - Open Banking PSD2 (AISP/PISP)", version=settings.APP_VERSION, lifespan=lifespan)
mount_security(app)


@app.post("/api/v1/consents", status_code=201)
async def request_consent(req: ConsentRequest):
    return SERVICE.request_consent(req.role, req.tpp_name, req.account_ids)


@app.post("/api/v1/authorize")
async def authorize(req: AuthorizeRequest):
    res = SERVICE.authorize(req.consent_id, req.approve, req.otp)
    if not res["authorised"]:
        raise HTTPException(status_code=403, detail=res)
    return res


@app.post("/api/v1/consents/{consent_id}/token")
async def exchange_code(consent_id: str, req: TokenRequest):
    res = SERVICE.exchange_code(consent_id, req.authorization_code)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res)
    return res


@app.post("/api/v1/initiations")
async def initiate_payment(req: InitiationRequest):
    res = SERVICE.initiate_payment(req.consent_id, req.access_token, req.amount, req.currency)
    if not res["initiated"]:
        raise HTTPException(status_code=403, detail=res)
    return res


@app.delete("/api/v1/consents/{consent_id}")
async def revoke_consent(consent_id: str):
    return SERVICE.revoke_consent(consent_id)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "openbanking"}