"""3DS2 Simulation — challenge SCA (PSD2) avec OTP lab."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from fraud.schemas_3ds import ChallengeRequest, ChallengeResponse, ChallengeVerifyRequest
from shared.auth import TokenClaims, verify_token
from shared.events import emit_event
from shared.metrics import ACTIVE_CHALLENGES

router = APIRouter()
challenges_store: dict[str, dict] = {}


@router.post("/challenge", response_model=ChallengeResponse, status_code=status.HTTP_201_CREATED)
async def create_challenge(
    data: ChallengeRequest,
    claims: TokenClaims = Depends(verify_token),
):
    challenge_id = f"ch_{uuid.uuid4().hex[:16]}"
    otp_code = f"{random.randint(0, 999999):06d}"
    challenges_store[challenge_id] = {
        "challenge_id": challenge_id,
        "transaction_id": data.transaction_id,
        "otp_code": otp_code,
        "method": data.method,
        "status": "pending",
        "attempts": 0,
        "max_attempts": 3,
        "merchant_id": claims.merchant_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    ACTIVE_CHALLENGES.inc()
    emit_event(
        {
            "event_type": "3ds_challenge",
            "challenge_id": challenge_id,
            "merchant_id": claims.merchant_id,
            "method": data.method,
            "status": "pending",
        }
    )
    # Lab only: OTP renvoyé dans le message pour la démo. Jamais en production.
    return ChallengeResponse(
        challenge_id=challenge_id,
        status="pending",
        method=data.method,
        message=f"OTP lab envoyé par {data.method} (code={otp_code})",
    )


@router.post("/verify-challenge")
async def verify_challenge(
    data: ChallengeVerifyRequest,
    claims: TokenClaims = Depends(verify_token),
):
    challenge = challenges_store.get(data.challenge_id)
    if not challenge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge non trouvé")
    if challenge["merchant_id"] != claims.merchant_id and "admin" not in claims.roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Challenge hors périmètre")
    if challenge["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Challenge déjà {challenge['status']}",
        )

    challenge["attempts"] += 1
    if challenge["attempts"] > challenge["max_attempts"]:
        challenge["status"] = "failed"
        ACTIVE_CHALLENGES.dec()
        emit_event({"event_type": "3ds_verify", "status": "lockout", "challenge_id": data.challenge_id})
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Trop de tentatives")

    if data.otp_code == challenge["otp_code"]:
        challenge["status"] = "verified"
        ACTIVE_CHALLENGES.dec()
        emit_event({"event_type": "3ds_verify", "status": "verified", "challenge_id": data.challenge_id})
        return {"challenge_id": data.challenge_id, "status": "verified", "message": "SCA OK"}

    remaining = challenge["max_attempts"] - challenge["attempts"]
    if remaining <= 0:
        challenge["status"] = "failed"
        ACTIVE_CHALLENGES.dec()
    emit_event({"event_type": "3ds_verify", "status": "failed", "challenge_id": data.challenge_id})
    return {
        "challenge_id": data.challenge_id,
        "status": "failed",
        "message": f"Code incorrect. {max(remaining, 0)} tentative(s) restante(s)",
    }
