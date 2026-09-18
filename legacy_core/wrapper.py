"""Adapter FastAPI — JSON in, COBOL out. Pas d'accès DB (least privilege)."""

from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from legacy_core.cobol_runner import decide
from legacy_core.sanitize import LegacyInputError, account_from_merchant, validate_account_id
from shared.events import emit_event
from shared.http import mount_security

app = FastAPI(
    title="SecurePay legacy-core (GnuCOBOL)",
    version="1.0.0",
    description="Simulateur core banking — binaire COBOL isolé, mTLS + validation stricte.",
)
mount_security(app)

RATE_LIMIT = int(os.getenv("LEGACY_CORE_RATE_LIMIT", "30"))
_hits: dict[str, list[float]] = defaultdict(list)


class ValidateRequest(BaseModel):
    account_id: str | None = Field(default=None, max_length=32)
    merchant_id: str | None = Field(default=None, max_length=64)
    amount: float = Field(..., gt=0, le=999_999_999.99)


def _rate_limit(ip: str) -> None:
    now = time.time()
    window = [t for t in _hits[ip] if now - t < 60]
    if len(window) >= RATE_LIMIT:
        _hits[ip] = window
        raise HTTPException(status_code=429, detail="Rate limit core banking (protection mainframe)")
    window.append(now)
    _hits[ip] = window


@app.get("/health")
async def health():
    from legacy_core.cobol_runner import binary_path

    path = binary_path()
    return {
        "status": "healthy",
        "service": "legacy-core",
        "cobol_binary": path.is_file(),
        "mtls": os.getenv("LEGACY_CORE_TLS", "0") in {"1", "true"},
    }


@app.post("/validate")
async def validate(body: ValidateRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    _rate_limit(ip)
    try:
        account = (
            validate_account_id(body.account_id)
            if body.account_id
            else account_from_merchant(body.merchant_id or "")
        )
        status = decide(account, body.amount)
    except LegacyInputError as exc:
        emit_event(
            {
                "event_type": "legacy_injection_blocked",
                "status": "blocked",
                "source_ip": ip,
                "reason": str(exc),
                "severity": "high",
            }
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="Core COBOL indisponible") from exc
    except Exception:
        raise HTTPException(status_code=502, detail="Erreur d'exécution COBOL") from None

    emit_event(
        {
            "event_type": "legacy_core_decision",
            "status": status.lower(),
            "account_id": account,
            "amount": body.amount,
            "source_ip": ip,
            "engine": "gnucobol",
        }
    )
    return {
        "status": status,
        "account": account,
        "amount": body.amount,
        "engine": "gnucobol",
    }
