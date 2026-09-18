"""Adaptateur DAB — ISO 8583 JSON in, REST SecurePay / moteur local out."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from atm import alm, aptra, argaus
from atm.engine import authorize
from atm.iso8583 import from_iso_amount, scenario_from_proc
from atm.journals import tail
from atm.kanest.runner import run_all
from atm.profiles_loader import list_vendors
from shared.http import mount_security

app = FastAPI(
    title="SecurePay ATM adapter (ISO 8583 lab)",
    version="1.0.0",
    description="Canal DAB simulé — KaNest/ARGAUS/APTRA/ALM lite. Pas de matériel NCR/Diebold réel.",
)
mount_security(app)


class IsoRequest(BaseModel):
    vendor: str = Field(default="ncr")
    atm_id: str = Field(default="DAB_PARIS_01")
    mti: str = "0200"
    named: dict[str, Any] = Field(default_factory=dict)
    scenario: str | None = None
    amount: float | None = None
    pan: str = "4111111111111111"


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "atm-adapter", "vendors": list_vendors()}


@app.post("/iso8583/authorize")
async def iso_authorize(body: IsoRequest):
    try:
        scenario = body.scenario or scenario_from_proc(str(body.named.get("processing_code") or "010000"))
        amount = body.amount if body.amount is not None else from_iso_amount(str(body.named.get("amount") or "0"))
        return await authorize(
            vendor=body.vendor,
            scenario=scenario,
            amount=amount,
            pan=body.named.get("pan") or body.pan,
            atm_id=body.atm_id,
            merchant_id=str(body.named.get("merchant_id") or "merchant-api"),
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/argaus/fleet")
async def fleet():
    return argaus.list_atms()


@app.post("/argaus/{atm_id}/status")
async def fleet_status(atm_id: str, status: str = "MAINTENANCE", reason: str = ""):
    try:
        return argaus.set_status(atm_id, status, reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="DAB inconnu") from exc


@app.get("/aptra/reports")
async def aptra_reports():
    return aptra.report()


@app.get("/journals/{kind}")
async def journals(kind: str, limit: int = 40):
    if kind not in {"mxa", "vte"}:
        raise HTTPException(status_code=400, detail="kind=mxa|vte")
    return tail(kind, limit=limit)


@app.post("/kanest/run")
async def kanest_run():
    return await run_all()


@app.get("/alm/pv", response_class=HTMLResponse)
async def alm_pv():
    path = Path(os.getenv("SECUREPAY_PV_DIR", "logs")) / "pv-recette-dab.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Lancer POST /kanest/run d'abord")
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.get("/alm/defects")
async def alm_list():
    return alm.list_defects()


@app.post("/alm/defects/{defect_id}/status")
async def alm_status(defect_id: str, status: str):
    try:
        return alm.transition(defect_id, status)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
