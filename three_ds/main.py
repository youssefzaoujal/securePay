"""3DS Server (3DSS) — construit l'AReq, échange avec le Directory Server (DS).

Rôle réel : le 3DS Server est un composant hébergé par le "3DS Requestor"
(le PSP/quicher), il génère le AReq, reçoit le ARes, initie le challenge UI
(CReq/CRes) et transmet le résultat RReq (CAVV + ECI) au moteur d'autorisation.

Références EMVCo : 3DS Core Spec v2.3.0 — EPC-2209 §3DS Server Functional.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from shared.events import emit_event
from shared.http import mount_security
from shared.metrics import ACTIVE_CHALLENGES
from three_ds.schemas import (
    AuthenticationRequest,
    AuthenticationResponse,
    ChallengeRequest,
    ChallengeResponse,
    MerchantInfo,
    ResultRequest,
    ResultResponse,
    ThreeDSAuthInput,
    ThreeDSResult,
    TransStatus,
    TransactionInfo,
)

DS_URL = os.getenv("DS_URL", "http://localhost:8021/api/v1/ds")
ACS_URL = os.getenv("ACS_URL", "http://localhost:8022/api/v1/acs")

_sessions: dict[str, dict[str, Any]] = {}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ds_auth_header() -> str:
    """Auth 3DS Server → DS. Lab : HMAC partagé. Prod : mTLS via Istio."""
    secret = os.getenv("THREEDS_SECRET", "lab-3ds-shared-secret")
    ts = str(int(datetime.now(timezone.utc).timestamp()))
    mac = hmac.new(secret.encode(), f"securepay-3dss|{ts}".encode(), hashlib.sha256).hexdigest()
    return f"HMAC {ts}:{mac}"


def build_areq(input_data: ThreeDSAuthInput) -> AuthenticationRequest:
    """Construit l'AReq conforme EMVCo 3DS Core Spec v2.3 §A.2."""
    three_ds_server_trans_id = f"3dss_{uuid.uuid4().hex[:24]}"
    now = datetime.now(timezone.utc)
    device_channel = (input_data.device_channel or "BROWSER").upper()

    areq = AuthenticationRequest(
        three_ds_server_trans_id=three_ds_server_trans_id,
        merchant=MerchantInfo(
            merchant_id=input_data.merchant_id,
            merchant_country_code="FR",
        ),
        transaction=TransactionInfo(
            amount=input_data.amount,
            currency=input_data.currency,
            date=now.strftime("%Y%m%d%H%M%S"),
        ),
        card={"token": input_data.card_token, "last_four": input_data.card_last_four},
        device=input_data.device_info or {"device_channel": device_channel, "device_ip": input_data.ip_address},
        cardholder=None,
    )
    if device_channel == "BROWSER":
        areq.browser = {
            "browser_accept_header": "*/*",
            "browser_ip": input_data.ip_address,
            "browser_language": "fr-FR",
            "browser_user_agent": "SecurePayLab/1.0",
        }
    return areq


def store_session(trans_id: str, data: dict[str, Any]) -> None:
    _sessions[trans_id] = {**data, "created_at": datetime.now(timezone.utc).isoformat()}


def get_session(trans_id: str) -> dict[str, Any] | None:
    return _sessions.get(trans_id)


def _eci_for(trans_status: TransStatus) -> str:
    """ECI mapping — EMVCo 3DS Core Spec v2.3 §A.4 (eci values)."""
    return {
        TransStatus.Y: "05",
        TransStatus.A: "06",
        TransStatus.U: "07",
        TransStatus.N: "07",
        TransStatus.R: "07",
    }.get(trans_status, "07")


def _generate_cavv(trans_status: TransStatus) -> str:
    """CAVV : 21 octets Base64 (28 chars) EMVCo-like.

    Un HSM réel (Thales/Gemalto/Utimaco) génère cette valeur hors couche
    applicative — voir `hsm/` (SoftHSM2 + PKCS#11). Lab : HMAC-SHA256 tronqué.
    """
    if trans_status == TransStatus.N:
        return ""
    seed = f"{trans_status.value}|{secrets.token_hex(8)}"
    return base64.b64encode(hashlib.sha256(seed.encode()).digest()[:21]).decode()


# ──────────────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SecurePay - EMV 3DS Server",
    version="2.3.0",
    description="3DS Requestor-side server. AReq→DS→ACS, challenge, CAVV+ECI propagation.",
)
mount_security(app)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "three-ds-server",
        "protocol": "EMVCo 3DS 2.3.0 + legacy 1.0",
        "sessions": len(_sessions),
    }


class ResolveChallengeBody(BaseModel):
    """Complétion d'un challenge par le gateway (OTP lab)."""
    three_ds_server_trans_id: str
    otp_code: str = Field(..., min_length=3, max_length=8)


@app.post("/api/v1/authenticate", response_model=ThreeDSResult)
async def authenticate(data: ThreeDSAuthInput, request: Request):
    """Point d'entrée principal — appelé par le gateway.

    1. Build AReq (EMVCo §A.2)
    2. AReq → DS (simule Visa/Mastercard)
    3. DS route vers ACS :
       - frictionless ⇒ transStatus=Y, CAVV généré
       - challenge ⇒ transStatus=C, acs_url renvoyé
    4. Résultat (CAVV+ECI) propagé à l'orchestrateur de paiement.
    """
    areq = build_areq(data)
    store_session(
        areq.three_ds_server_trans_id,
        {"areq": areq.model_dump(mode="json"), "input": data.model_dump(mode="json")},
    )

    ares = await _call_ds(areq)
    _sessions[areq.three_ds_server_trans_id]["ares"] = ares.model_dump(mode="json")

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds2_areq",
            "three_ds_server_trans_id": areq.three_ds_server_trans_id,
            "merchant_id": data.merchant_id,
            "amount": data.amount,
            "trans_status": ares.trans_status.value,
            "challenge": ares.trans_status == TransStatus.C,
            "source_ip": data.ip_address,
        }
    )

    if ares.trans_status == TransStatus.C:
        ACTIVE_CHALLENGES.inc()
        return ThreeDSResult(
            trans_status=TransStatus.C,
            three_ds_server_trans_id=areq.three_ds_server_trans_id,
            acs_trans_id=ares.acs_trans_id,
            ds_trans_id=ares.ds_trans_id,
            challenge_required=True,
            challenge_id=areq.three_ds_server_trans_id,
            acs_url=ares.acs_url,
        )

    return ThreeDSResult(
        trans_status=ares.trans_status,
        eci=ares.eci,
        cavv=ares.cavv,
        three_ds_server_trans_id=areq.three_ds_server_trans_id,
        acs_trans_id=ares.acs_trans_id,
        ds_trans_id=ares.ds_trans_id,
        challenge_required=False,
    )


async def _call_ds(areq: AuthenticationRequest) -> AuthenticationResponse:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{DS_URL}/authenticate",
            json=areq.model_dump(mode="json"),
            headers={
                "X-DS-Auth": _ds_auth_header(),
                "X-Correlation-ID": areq.three_ds_server_trans_id,
            },
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=response.status_code,
                detail=response.json() if response.content else response.text,
            )
        return AuthenticationResponse(**response.json())


@app.post("/api/v1/challenge/complete")
async def complete_challenge(body: ResolveChallengeBody, request: Request):
    """Le gateway finalise le challenge : CReq → ACS → CRes → RReq→RRes."""
    session = get_session(body.three_ds_server_trans_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session 3DS inconnue")

    ares = AuthenticationResponse(**session["ares"])
    creq = ChallengeRequest(
        three_ds_server_trans_id=body.three_ds_server_trans_id,
        acs_trans_id=ares.acs_trans_id or "",
        otp_code=body.otp_code,
    )
    cres = await _creq_to_acs(creq)
    ACTIVE_CHALLENGES.dec()

    rreq = ResultRequest(
        three_ds_server_trans_id=body.three_ds_server_trans_id,
        acs_trans_id=ares.acs_trans_id or "",
        ds_trans_id=ares.ds_trans_id,
        trans_status=cres.trans_status,
        eci=_eci_for(cres.trans_status),
        cavv=_generate_cavv(cres.trans_status),
        cavv_algorithm="01",
    )
    rres = await _send_rreq(rreq)

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds2_challenge_result",
            "three_ds_server_trans_id": body.three_ds_server_trans_id,
            "trans_status": rreq.trans_status.value,
            "eci": rreq.eci,
            "cavv_present": bool(rreq.cavv),
            "status": "ok",
        }
    )
    return ThreeDSResult(
        trans_status=rreq.trans_status,
        eci=rreq.eci,
        cavv=rreq.cavv,
        three_ds_server_trans_id=body.three_ds_server_trans_id,
        acs_trans_id=rres.acs_trans_id,
        ds_trans_id=ares.ds_trans_id,
        challenge_required=False,
    )


async def _creq_to_acs(creq: ChallengeRequest) -> ChallengeResponse:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{ACS_URL}/challenge",
            json=creq.model_dump(mode="json"),
            headers={"X-DS-Auth": _ds_auth_header()},
        )
        response.raise_for_status()
        return ChallengeResponse(**response.json())


async def _send_rreq(rreq: ResultRequest) -> ResultResponse:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{DS_URL}/result",
            json=rreq.model_dump(mode="json"),
            headers={"X-DS-Auth": _ds_auth_header()},
        )
        response.raise_for_status()
        return ResultResponse(**response.json())