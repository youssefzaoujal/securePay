"""Rédaction PCI-DSS : aucun PAN, CVV, secret ou JWT complet dans les logs."""

from __future__ import annotations

import re
from typing import Any

_PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_CVV_FIELD_RE = re.compile(
    r"(?i)([\"']?(?:cvv|cvc|cid|card_cvv)[\"']?\s*[:=]\s*[\"']?)\d{3,4}"
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*")
_KEY_RE = re.compile(
    r"(?i)([\"']?(?:password|secret|token|api_key|authorization)[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+"
)


def mask_pan(value: str) -> str:
    """Remplace un PAN par **** + 4 derniers chiffres (PCI-DSS Req 3.3)."""
    digits = re.sub(r"[^0-9]", "", value)
    if 13 <= len(digits) <= 19:
        return f"****{digits[-4:]}"
    return "****"


def redact_secrets(value: Any) -> Any:
    """Rédige récursivement PAN, CVV, Bearer tokens et secrets."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = key.lower()
            if lowered in {"card_number", "pan", "primary_account_number"}:
                redacted[key] = mask_pan(str(item)) if item else item
            elif lowered in {"card_cvv", "cvv", "cvc", "cid"}:
                redacted[key] = "***"
            elif lowered in {"password", "secret", "client_secret", "encryption_key"}:
                redacted[key] = "***REDACTED***"
            elif lowered in {"authorization", "access_token", "refresh_token"}:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str):
        text = _PAN_RE.sub(lambda m: mask_pan(m.group(0)), value)
        text = _CVV_FIELD_RE.sub(r"\1***", text)
        text = _BEARER_RE.sub(r"\1***REDACTED***", text)
        text = _KEY_RE.sub(r"\1***REDACTED***", text)
        return text
    return value
