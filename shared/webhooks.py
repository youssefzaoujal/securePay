"""Webhooks HMAC-SHA256 — miroir de la sécu PSP (Stripe/Adyen style)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any

from config import get_settings


def _webhook_secret() -> bytes:
    try:
        secret = get_settings().WEBHOOK_SECRET
    except Exception:
        secret = os.getenv("WEBHOOK_SECRET", "lab-webhook-secret-change-me")
    return (secret or "lab-webhook-secret-change-me").encode()


def sign_payload(payload: dict[str, Any], timestamp: int | None = None) -> tuple[str, str]:
    """Retourne (timestamp, signature hex). En-tête: X-SecurePay-Signature t=...,v1=..."""
    secret = _webhook_secret()
    ts = timestamp or int(time.time())
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str)
    message = f"{ts}.{body}".encode()
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return str(ts), signature


def verify_signature(payload: dict[str, Any], timestamp: str, signature: str, max_age: int = 300) -> bool:
    """Vérifie HMAC + fenêtre anti-replay (5 min par défaut)."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > max_age:
        return False
    _, expected = sign_payload(payload, timestamp=ts)
    return hmac.compare_digest(expected, signature)


def signature_header(timestamp: str, signature: str) -> str:
    return f"t={timestamp},v1={signature}"
