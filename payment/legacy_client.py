"""Client mTLS vers le simulateur COBOL (fail-closed hors lab)."""

from __future__ import annotations

import os
import ssl

import httpx

from config import get_settings
from legacy_core.sanitize import LegacyInputError, account_from_merchant


def mtls_context() -> ssl.SSLContext | bool:
    """Contexte SSL urllib-compatible — plus fiable qu'un tuple cert= sous httpx."""
    url = os.getenv("LEGACY_CORE_URL") or get_settings().LEGACY_CORE_URL
    if not url.startswith("https://"):
        return True
    ca = os.getenv("LEGACY_CORE_CA", "/certs/ca.crt")
    cert = os.getenv("LEGACY_CORE_CERT", "/certs/payment-client.crt")
    key = os.getenv("LEGACY_CORE_KEY", "/certs/payment-client.key")
    if not (os.path.isfile(ca) and os.path.isfile(cert) and os.path.isfile(key)):
        return True
    ctx = ssl.create_default_context(cafile=ca)
    ctx.load_cert_chain(cert, key)
    return ctx


async def call_legacy_core(merchant_id: str, amount: float) -> str | None:
    """Retourne APPROVED/DECLINED, ou None si le core n'est pas configuré."""
    settings = get_settings()
    base = (os.getenv("LEGACY_CORE_URL") or settings.LEGACY_CORE_URL or "").rstrip("/")
    if not base:
        return None
    try:
        account = account_from_merchant(merchant_id)
    except LegacyInputError:
        return "DECLINED"
    timeout = float(os.getenv("LEGACY_CORE_TIMEOUT", "2.5"))
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=mtls_context()) as client:
            response = await client.post(
                f"{base}/validate",
                json={"account_id": account, "merchant_id": merchant_id, "amount": amount},
            )
    except httpx.HTTPError:
        if settings.APP_ENV == "lab":
            return None
        raise
    if response.status_code == 429:
        return "DECLINED"
    if response.status_code >= 400:
        if settings.APP_ENV == "lab":
            return None
        return "DECLINED"
    status = str(response.json().get("status", "")).upper()
    if status in {"APPROVED", "DECLINED"}:
        return status
    return "DECLINED"
