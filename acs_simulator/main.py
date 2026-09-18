"""ACS Simulator — simule l'émetteur (banque) dans EMV 3DS 2.3.

Décisions :
  - frictionless  → transStatus=Y + CAVV + ECI tout de suite
  - challenge     → transStatus=C + acs_url (méthode OTP/biométrie simulée)
  - reject / fail → transStatus=N/R/U selon le score risque interne

Le scoring ACS réutilise la philosophie du moteur de fraude SecurePay
(amount, vélocité IP, device fingerprint) + une règle "émetteur" par BIN.

Références EMVCo : 3DS Core Spec v2.3.0 §3DS ACS Functional + ACS SDK.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from shared.events import emit_event
from shared.http import mount_security
from three_ds.schemas import (
    AuthenticationRequest,
    AuthenticationResponse,
    ChallengeRequest,
    ChallengeResponse,
    TransStatus,
)

ACS_SECRET = os.getenv("THREEDS_SECRET", "lab-3ds-shared-secret")

_acss: dict[str, dict[str, Any]] = {}
_challenges: dict[str, dict[str, Any]] = {}


class ACSScoringEngine:
    """Équivalent ACS RiskBasedAuthentication (RBA) — lab keep-it-deterministic."""

    def __init__(self) -> None:
        self._ip_history: dict[str, list[float]] = {}
        self._token_history: dict[str, list[float]] = {}

    def score(
        self,
        amount: float,
        currency: str,
        card_token: str,
        ip_address: str,
        device_fingerprint_score: float | None = None,
        bin_profile_threshold: float = 0.5,
    ) -> dict[str, Any]:
        score = 0.0
        flags: list[str] = []

        now = time.time()
        self._ip_history.setdefault(ip_address or "unknown", []).append(now)
        self._token_history.setdefault(card_token, []).append(now)
        for hist in (self._ip_history.get(ip_address), self._token_history.get(card_token)):
            if hist:
                while hist and now - hist[0] > 60:
                    hist.pop(0)

        if amount > 10000:
            score += 0.45
            flags.append("amount_exceeds_high_threshold")
        elif amount > 2500:
            score += 0.25
            flags.append("amount_elevated")

        if len(self._token_history[card_token]) >= 6:
            score += 0.35
            flags.append("token_velocity")

        if ip_address:
            if len(self._ip_history[ip_address]) >= 15:
                score += 0.30
                flags.append("ip_velocity")
            if ip_address.startswith(("10.255.", "192.0.2.", "198.51.100.")):
                score += 0.25
                flags.append("high_risk_ip_lab_range")

        if device_fingerprint_score:
            score += min(0.4, device_fingerprint_score * 0.4)
            flags.append("device_anomaly")

        risk = round(min(score, 1.0), 4)
        if risk >= 0.85:
            decision, trans_status = "reject", TransStatus.R
        elif risk >= bin_profile_threshold:
            decision, trans_status = "challenge", TransStatus.C
        else:
            decision, trans_status = "frictionless", TransStatus.Y

        return {
            "risk_score": risk,
            "flags": flags,
            "decision": decision,
            "trans_status": trans_status,
        }


_scoring = ACSScoringEngine()


# ──────────────────────────────────────────────────────────────────────────────
# Helpers crypto (ACS = entité qui signe le CAVV)
# ──────────────────────────────────────────────────────────────────────────────

def _sign_acs(trans_status: TransStatus, acs_trans_id: str) -> str:
    """CAVV simulé — HMAC-SHA256 tronqué à 21 octets + Base64 (28 chars)."""
    if trans_status == TransStatus.N:
        return ""
    seed = f"acs|{acs_trans_id}|{trans_status.value}|{secrets.token_hex(4)}"
    return base64.b64encode(
        hmac.new(ACS_SECRET.encode(), seed.encode(), hashlib.sha256).digest()[:21]
    ).decode()


def _eci_for(trans_status: TransStatus) -> str:
    return {
        TransStatus.Y: "05",
        TransStatus.A: "06",
        TransStatus.U: "07",
        TransStatus.N: "07",
        TransStatus.R: "07",
    }.get(trans_status, "07")


def _verify_ds_auth(request: Request) -> bool:
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
        ACS_SECRET.encode(), b"ds|acs", hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, mac)


def _selected_bin_threshold(areq: AuthenticationRequest) -> float:
    """Ambient challenge rate par BIN (reflète la politique émetteur)."""
    hints = {
        "411111": 0.18,
        "400000": 0.10,
        "555555": 0.35,
        "510510": 0.15,
        "378282": 0.05,
        "371449": 0.05,
    }
    pan = areq.card.get("token") or ""
    return hints.get(pan[:6], 0.25)


app = FastAPI(
    title="SecurePay - ACS Simulator (Issuer)",
    version="2.3.0",
    description="Simule la banque émettrice : RBA, challenge OTP/biométrie, CAVV+ECI.",
)
mount_security(app)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "acs-simulator",
    }


@app.post("/api/v1/acs/authenticate", response_model=AuthenticationResponse)
async def authenticate(areq: AuthenticationRequest, request: Request):
    """Décide frictionless vs challenge (RBA interne) puis renvoie l'ARes."""
    if not _verify_ds_auth(request):
        raise HTTPException(status_code=401, detail="Authentification DS invalide")

    acs_trans_id = f"acs_{uuid.uuid4().hex[:20]}"
    ds_trans_id = f"ds_{uuid.uuid4().hex[:20]}"
    device_score = _extract_device_score(areq)
    result = _scoring.score(
        amount=areq.transaction.amount,
        currency=areq.transaction.currency,
        card_token=areq.card.get("token", ""),
        ip_address=areq.device.get("device_ip") if isinstance(areq.device, dict) else "",
        device_fingerprint_score=device_score,
        bin_profile_threshold=_selected_bin_threshold(areq),
    )

    _acss[acs_trans_id] = {
        "three_ds_server_trans_id": areq.three_ds_server_trans_id,
        "ds_trans_id": ds_trans_id,
        "trans_status": result["trans_status"].value,
        "risk_score": result["risk_score"],
        "flags": result["flags"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds2_acs_decision",
            "three_ds_server_trans_id": areq.three_ds_server_trans_id,
            "acs_trans_id": acs_trans_id,
            "merchant_id": areq.merchant.merchant_id,
            "bin_hint": (areq.card.get("token") or "")[:6],
            "decision": result["decision"],
            "trans_status": result["trans_status"].value,
            "risk_score": result["risk_score"],
            "flags": result["flags"],
            "status": "ok",
        }
    )

    if result["trans_status"] == TransStatus.C:
        challenge_id = f"ch_{uuid.uuid4().hex[:16]}"
        _challenges[challenge_id] = {
            "acs_trans_id": acs_trans_id,
            "three_ds_server_trans_id": areq.three_ds_server_trans_id,
            "status": "pending",
            "method": "otp-sms",
            "otp_code": f"{secrets.randbelow(1000000):06d}",
            "attempts": 0,
        }
        return AuthenticationResponse(
            three_ds_server_trans_id=areq.three_ds_server_trans_id,
            acs_trans_id=acs_trans_id,
            ds_trans_id=ds_trans_id,
            trans_status=TransStatus.C,
            trans_status_reason="Cardholder authentication required",
            acs_challenge_mandated="Y",
            acs_url=f"/api/v1/acs/challenge/{challenge_id}",
            challenge_type="02",
            whitelisting_status="absent",
        )

    return AuthenticationResponse(
        three_ds_server_trans_id=areq.three_ds_server_trans_id,
        acs_trans_id=acs_trans_id,
        ds_trans_id=ds_trans_id,
        trans_status=result["trans_status"],
        trans_status_reason=None,
        eci=_eci_for(result["trans_status"]),
        cavv=_sign_acs(result["trans_status"], acs_trans_id),
        cavv_algorithm="01",
        acs_challenge_mandated="N",
        whitelisting_status="absent",
    )


def _extract_device_score(areq: AuthenticationRequest) -> float | None:
    device = areq.device
    if isinstance(device, dict):
        if (device.get("device_score") or device.get("device_fraud_score")) is not None:
            return float(device.get("device_score") or device.get("device_fraud_score"))
        if device.get("device_fingerprint"):
            try:
                digest = hashlib.sha256(str(device["device_fingerprint"]).encode()).digest()
                return int.from_bytes(digest[:4], "big") / 2**32
            except Exception:
                return None
    return None


class ChallengeCompleteBody(BaseModel):
    otp_code: str | None = None
    biometric_sample: str | None = None


@app.post("/api/v1/acs/challenge", response_model=ChallengeResponse)
async def complete_challenge(creq: ChallengeRequest, body: ChallengeCompleteBody | None = None):
    """CReq → CRes. Lab : l'OTP du challenge arrive dans le CReq `otp_code`."""
    if not body:
        body = ChallengeCompleteBody(otp_code=creq.otp_code)

    ares_key = creq.acs_trans_id
    record = _acss.get(ares_key)
    if not record:
        raise HTTPException(status_code=404, detail="ACS trans inconnue")

    challenge_id = next(
        (cid for cid, ch in _challenges.items() if ch["acs_trans_id"] == ares_key),
        None,
    )
    if not challenge_id:
        raise HTTPException(status_code=404, detail="Challenge absent")

    challenge = _challenges[challenge_id]
    challenge["attempts"] += 1
    if challenge["attempts"] > 3:
        challenge["status"] = "failed"
        emit_event(
            {"event_type": "three_ds", "scenario": "3ds2_challenge_lockout", "status": "failed"}
        )
        return ChallengeResponse(
            message_type="CRes",
            three_ds_server_trans_id=creq.three_ds_server_trans_id,
            acs_trans_id=creq.acs_trans_id,
            trans_status=TransStatus.N,
        )

    if body.otp_code and hmac.compare_digest(body.otp_code, challenge["otp_code"]):
        challenge["status"] = "verified"
        emit_event(
            {
                "event_type": "three_ds",
                "scenario": "3ds2_challenge_ok",
                "three_ds_server_trans_id": creq.three_ds_server_trans_id,
                "status": "verified",
            }
        )
        return ChallengeResponse(
            message_type="CRes",
            three_ds_server_trans_id=creq.three_ds_server_trans_id,
            acs_trans_id=creq.acs_trans_id,
            trans_status=TransStatus.Y,
        )

    emit_event(
        {
            "event_type": "three_ds",
            "scenario": "3ds2_challenge_fail",
            "three_ds_server_trans_id": creq.three_ds_server_trans_id,
            "status": "otp_invalid",
        }
    )
    return ChallengeResponse(
        message_type="CRes",
        three_ds_server_trans_id=creq.three_ds_server_trans_id,
        acs_trans_id=creq.acs_trans_id,
        trans_status=TransStatus.N,
    )


@app.get("/api/v1/acs/challenges")
async def list_challenges():
    sanitized = [
        {**ch, "otp_code": "***"} for ch in _challenges.values()
    ]
    return {"count": len(_challenges), "challenges": sanitized}


@app.get("/api/v1/acs/decisions")
async def decisions():
    return {"count": len(_acss), "decisions": list(_acss.values())[-50:]}