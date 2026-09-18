"""Tokenization routes — coffre PAN, jamais de CVV, jamais de PAN côté payment."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from shared.auth import TokenClaims, require_role, verify_token
from shared.events import emit_event
from shared.luhn import detect_brand, luhn_ok
from tokenization.crypto import decrypt_token, encrypt_card
from tokenization.schemas import DetokenizeRequest, TokenizeRequest, TokenizeResponse

router = APIRouter()

# Lab vault (process-local). Persisté en Postgres dès que le pool est dispo.
_VAULT: dict[str, dict] = {}


@router.post("/tokenize", response_model=TokenizeResponse, status_code=status.HTTP_201_CREATED)
async def tokenize_card(
    data: TokenizeRequest,
    claims: TokenClaims = Depends(verify_token),
):
    pan = "".join(ch for ch in data.card_number if ch.isdigit())
    if not luhn_ok(pan):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="PAN invalide (Luhn) — simulation: utiliser 4111111111111111",
        )

    token = f"tok_{uuid.uuid4().hex[:24]}"
    last_four = pan[-4:]
    brand = detect_brand(pan)
    encrypted = encrypt_card(pan, data.card_expiry, data.card_cvv)

    _VAULT[token] = {
        "encrypted_pan": encrypted["encrypted_pan"],
        "encrypted_expiry": encrypted["encrypted_expiry"],
        "last_four": last_four,
        "card_brand": brand,
        "merchant_id": claims.merchant_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "cvv_stored": False,
    }

    emit_event(
        {
            "event_type": "tokenize",
            "merchant_id": claims.merchant_id,
            "card_brand": brand,
            "card_last_four": last_four,
            "status": "ok",
        }
    )

    return TokenizeResponse(
        token=token,
        last_four=last_four,
        card_brand=brand,
        expires_at=data.card_expiry,
        algorithm="AES-256-GCM",
        cvv_stored=False,
    )


@router.post("/detokenize")
async def detokenize_card(
    data: DetokenizeRequest,
    claims: TokenClaims = Depends(require_role("admin", "tokenization-service")),
):
    """Détokenisation interne uniquement — le payment service ne l'appelle jamais."""
    entry = _VAULT.get(data.token)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token inconnu")
    decrypted = decrypt_token(entry)
    emit_event(
        {
            "event_type": "detokenize",
            "merchant_id": claims.merchant_id,
            "status": "ok",
            "card_last_four": entry["last_four"],
        }
    )
    return {
        "last_four": entry["last_four"],
        "card_brand": entry["card_brand"],
        "card_expiry": decrypted["card_expiry"],
        "pan_redacted": f"****{entry['last_four']}",
    }


@router.get("/tokens/{token}")
async def get_token_metadata(token: str, claims: TokenClaims = Depends(verify_token)):
    entry = _VAULT.get(token)
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token inconnu")
    return {
        "token": token,
        "last_four": entry["last_four"],
        "card_brand": entry["card_brand"],
        "cvv_stored": False,
        "algorithm": "AES-256-GCM",
    }
