"""Validation stricte avant tout appel au binaire COBOL (anti-injection argv)."""

from __future__ import annotations

import math
import re

ACCOUNT_RE = re.compile(r"^[A-Z0-9]{1,10}$")
MAX_AMOUNT = 999_999_999.99


class LegacyInputError(ValueError):
    """Entrée rejetée — ne jamais la passer à subprocess."""


def account_from_merchant(merchant_id: str) -> str:
    """Dérive un ID compte PIC X(10) depuis le merchant JWT (pas de caractères spéciaux)."""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", merchant_id or "").upper()
    if not cleaned:
        raise LegacyInputError("merchant_id vide après sanitization")
    return cleaned[:10]


def validate_account_id(account_id: str) -> str:
    value = (account_id or "").strip().upper()
    if not ACCOUNT_RE.fullmatch(value):
        raise LegacyInputError("account_id invalide (A-Z0-9, 1-10 car.)")
    return value


def validate_amount(amount: float) -> float:
    try:
        value = float(amount)
    except (TypeError, ValueError) as exc:
        raise LegacyInputError("amount non numérique") from exc
    if math.isnan(value) or math.isinf(value) or value <= 0 or value > MAX_AMOUNT:
        raise LegacyInputError("amount hors bornes")
    return round(value, 2)


def cents(amount: float) -> str:
    """Montant en centimes, chiffres uniquement — aucun signe, aucun shell metachar."""
    safe = validate_amount(amount)
    return str(int(round(safe * 100)))
