"""API Network Tokenization (VTS/MDES-like) — Phase 3."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field

from config import get_settings
from network_token.service import SERVICE
from shared.http import mount_security

settings = get_settings()


class ProvisionRequest(BaseModel):
    pan: str = Field(..., min_length=16, max_length=19, description="PAN réseau (lab uniquement)")
    domain: str
    idempotency_key: str | None = None


class AuthenticateRequest(BaseModel):
    token_reference: str
    cryptogram: str
    domain: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="SecurePay - Network Tokenization (VTS/MDES sim)", version=settings.APP_VERSION, lifespan=lifespan)
mount_security(app)


@app.post("/api/v1/tokens/provision", status_code=201)
async def provision(req: ProvisionRequest):
    return SERVICE.provision(req.pan, req.domain, req.idempotency_key)


@app.post("/api/v1/tokens/authenticate")
async def authenticate(req: AuthenticateRequest):
    return SERVICE.authenticate(req.token_reference, req.cryptogram, req.domain)


@app.delete("/api/v1/tokens/{token_reference}/deactivate")
async def deactivate(token_reference: str):
    return SERVICE.deactivate(token_reference)


@app.get("/api/v1/tokens/{token_reference}")
async def status(token_reference: str):
    return SERVICE.status(token_reference)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "network-token"}