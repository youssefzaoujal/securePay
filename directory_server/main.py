"""Directory Server (DS) — simule le rôle réseau (Visa/Mastercard) dans EMV 3DS.

Le DS :
  - vérifie l'authenticité du 3DS Server/Requestor (certificats ou HMAC lab)
  - route l'AReq vers le bon ACS (simulation : fichier de mapping)
  - retourne l'ARes au 3DS Server
  - reçoit le RReq final et produit le RRes (buffer des résultats pour logs/audit)

Références EMVCo : 3DS Core Spec v2.3.0 §3DS Directory Server Functional.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from shared.events import emit_event
from shared.http import mount_security
from three_ds.schemas import (
    AuthenticationRequest,
    AuthenticationResponse,
    ResultRequest,
    ResultResponse,
    TransStatus,
)

ACS_URL = os.getenv("ACS_URL", "http://localhost:8022/api/v1/acs")
DS_SECRET = os.getenv("THREEDS_SECRET", "lab-3ds-shared-secret")

# Mapping BIN → ACS (simulation du réseau) : le BIN dirige vers l'émetteur.
BIN_TO_ACS: dict[str, str] = {
    "411111": "securepay-acs",  # Visa lab
    "400000": "securepay-acs",
    "555555": "securepay-acs",  # Mastercard lab
    "510510": "securepay-acs",
    "378282": "securepay-acs",  # Amex
    "371449": "securepay-acs",
}

# Mapping BIN → risque de challenge (simulation des règles émetteur/réseau).
# En prod, ce sont les règles du réseau (Visa Risk / MC Risk) + l'ACS.
BIN_CHALLENGE_PROFILE: dict[str, float] = {
    "411111": 0.20,  # 20% de challenge pour cette BIN
    "400000": 0.10,
    "555555": 0.35,
    "510510": 0.15,
    "378282": 0.05,
    "371449": 0.05,
}

_result_buffer: list[dict[str, Any]] = []
_MAX_BUFFER = 500


def _verify_ds_auth(request: Request) -> bool:
    """Vérifie l'en-tête X-DS-Auth (HMAC lab) — prod : mTLS via Istio/SPIFFE."""
    header = request.headers.get("x-ds-auth", "")
    if not header or not header.startswith("HMAC "):
        return False
    ts_part, mac = header[5:].split(":", 1)
    try:
        ts = int(ts_part)
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > 120:
        return False
    expected = hmac.new(
        DS_SECRET.encode(), f"securepay-3dss|{ts}".encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, mac)


def _resolve_acs(pan_token: str) -> str:
    return BIN_TO_ACS.get(pan_token[:6], "securepay-acs") if pan_token else "securepay-acs"


async def _forward_to_acs(areq: AuthenticationRequest, acs_name: str) -> AuthenticationResponse:
    """Route AReq → ACS. Renvoie l'ARes."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{ACS_URL}/authenticate",
            json=areq.model_dump(mode="json"),
            headers={
                "X-DS-Auth": f"HMAC {int(time.time())}:{hmac.new(DS_SECRET.encode(), b'ds|acs', hashlib.sha256).hexdigest()}",
                "X-ACS-Name": acs_name,
            },
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=502,
                detail=f"ACS {acs_name} retourne une erreur: {response.text[:200]}",
            )
        return AuthenticationResponse(**response.json())


app = FastAPI(
    title="SecurePay - Directory Server (3DS Network)",
    version="2.3.0",
    description="Simule Visa/Mastercard role : verify Requestor, route AReq→ACS, RReq/RRes.",
)
mount_security(app)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "directory-server",
        "acs_routes": len(BIN_TO_ACS),
        "result_buffer": len(_result_buffer),
    }


@app.post("/api/v1/ds/authenticate", response_model=AuthenticationResponse)
async def authenticate(areq: AuthenticationRequest, request: Request):
    """Reçoit l'AReq d'un 3DS Server, vérifie le Requestor, route vers ACS."""
    if not _verify_ds_auth(request):
        raise HTTPException(status_code=401, detail="Authentification 3DS Server invalide")

    pan_hint = areq.card.get("token") or ""
    acs_name = _resolve_acs(pan_hint)

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds2_ds_route",
            "three_ds_server_trans_id": areq.three_ds_server_trans_id,
            "merchant_id": areq.merchant.merchant_id,
            "amount": areq.transaction.amount,
            "acs": acs_name,
            "bin_hint": pan_hint[:6],
            "status": "routed",
        }
    )

    ares = await _forward_to_acs(areq, acs_name)

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds2_ares",
            "three_ds_server_trans_id": areq.three_ds_server_trans_id,
            "trans_status": ares.trans_status.value,
            "acs_trans_id": ares.acs_trans_id,
            "ds_trans_id": ares.ds_trans_id,
            "status": "ok",
        }
    )
    return ares


@app.post("/api/v1/ds/result", response_model=ResultResponse)
async def result(rreq: ResultRequest, request: Request):
    """Reçoit le RReq (résultat du challenge), bufferise pour audit réseau."""
    if not _verify_ds_auth(request):
        raise HTTPException(status_code=401, detail="Authentification invalide")

    entry = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "three_ds_server_trans_id": rreq.three_ds_server_trans_id,
        "acs_trans_id": rreq.acs_trans_id,
        "trans_status": rreq.trans_status.value,
        "eci": rreq.eci,
        "cavv_present": bool(rreq.cavv),
    }
    _result_buffer.append(entry)
    if len(_result_buffer) > _MAX_BUFFER:
        del _result_buffer[:-_MAX_BUFFER]

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds2_rreq",
            "three_ds_server_trans_id": rreq.three_ds_server_trans_id,
            "trans_status": rreq.trans_status.value,
            "eci": rreq.eci,
            "status": "recorded",
        }
    )
    return ResultResponse(
        three_ds_server_trans_id=rreq.three_ds_server_trans_id,
        acs_trans_id=rreq.acs_trans_id,
        acs_rendering_type="OOB",
    )


@app.get("/api/v1/ds/routes")
async def routes():
    """Expose la table de routage BIN→ACS (simulation réseau)."""
    return {"routes": BIN_TO_ACS, "challenge_profiles": BIN_CHALLENGE_PROFILE}


@app.get("/api/v1/ds/results")
async def results(limit: int = 50):
    """Tampon d'audit des RReq reçus (réserve de performance/networking)."""
    return {"count": len(_result_buffer), "results": _result_buffer[-limit:]}