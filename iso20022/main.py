"""API ISO 20022 — construction / parsing des messages bancaires (Phase 3)."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from config import get_settings
from iso20022.messages import (
    AccountStatement,
    CreditTransfer,
    PaymentStatusReport,
    _STATUS_VALID,
    validate_iban,
)
from shared.http import mount_security

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="SecurePay - ISO 20022", version=settings.APP_VERSION, lifespan=lifespan)
mount_security(app)


@app.post("/api/v1/pacs008")
async def build_pacs008(ct: CreditTransfer):
    if ct.amount <= 0:
        raise HTTPException(status_code=400, detail="montant invalide")
    if not validate_iban(ct.debtor_iban) or not validate_iban(ct.creditor_iban):
        raise HTTPException(status_code=400, detail="IBAN invalide")
    return {"message_type": "pacs.008.001.08", "xml": ct.build()}


@app.post("/api/v1/pacs008/parse")
async def parse_pacs008(body: dict):
    xml = body.get("xml", "")
    try:
        return {"message_type": "pacs.008.001.08", "fields": CreditTransfer.load(CreditTransfer(), xml)}
    except Exception:
        raise HTTPException(status_code=400, detail="XML invalide")


@app.post("/api/v1/pacs002", status_code=201)
async def build_pacs002(r: PaymentStatusReport):
    if r.status not in _STATUS_VALID:
        raise HTTPException(status_code=400, detail=f"status inconnu: {r.status}")
    return {"message_type": "pacs.002.001.10", "xml": r.build()}


@app.post("/api/v1/camt053")
async def build_camt053(s: AccountStatement):
    return {"message_type": "camt.053.001.08", "xml": s.build()}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "iso20022"}