"""Open Banking / PSD2 — consentement OAuth2, rôles AISP/PISP (Phase 3).

Modèle : la banque expose un flow "authorization code" pour un **consentement
d'intermédiaire** :
  1. TPP (AISP/PISP) demande un consentement via /consents → consent_id + redirect
  2. L'utilisateur autorise via /authorize (l'API banque simulée)
  3. TPP échange le code → access_token scoped au consentement
  4. PISP initie un paiement : le paiement exige UNE consent_id active (SCA listé)

Contrats PSD2 RTS 2018/389 : SCA obligatoire pour PISP, pas de contournement.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode

ROLE_AISP = "aisp"
ROLE_PISP = "pisp"


@dataclass
class Consent:
    consent_id: str
    role: str                      # aisp | pisp
    tpp_name: str
    account_ids: list[str] = field(default_factory=list)
    sca_method: str = "OTP-SMS-lab"
    status: str = "PENDING"         # PENDING | AUTHORISED | REVOKED
    authorization_code: Optional[str] = None
    access_token: Optional[str] = None
    amount_limit: float | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class OpenBankingService:
    """Simulation de l'API banque (consent + token + payment initiation)."""

    def __init__(self):
        self._consents: dict[str, Consent] = {}

    def request_consent(self, role: str, tpp_name: str, account_ids: list[str] | None = None, amount_limit: float | None = None) -> dict:
        if role not in (ROLE_AISP, ROLE_PISP):
            raise ValueError(f"rôle inconnu: {role}")
        consent = Consent(
            consent_id=f"csnt_{secrets.token_hex(8)}",
            role=role,
            tpp_name=tpp_name,
            account_ids=account_ids or [],
            amount_limit=amount_limit,
        )
        self._consents[consent.consent_id] = consent
        redirect = self.authorize_url(consent.consent_id)
        return {
            "consent_id": consent.consent_id,
            "status": consent.status,
            "redirect_uri": redirect,
            "sca_method": consent.sca_method,
        }

    def authorize_url(self, consent_id: str) -> str:
        query = urlencode({"consent_id": consent_id, "state": f"st_{secrets.token_hex(4)}"})
        return f"/openbanking/authorize?{query}"

    def authorize(self, consent_id: str, approve: bool = True, otp: str = "123456") -> dict:
        consent = self._consents.get(consent_id)
        if not consent:
            return {"authorised": False, "reason": "unknown_consent"}
        if consent.status not in ("PENDING", "AUTHORISED"):
            return {"authorised": False, "reason": "consent_not_pending"}
        if not approve:
            consent.status = "REVOKED"
            return {"authorised": False, "reason": "user_denied"}
        consent.status = "AUTHORISED"
        consent.authorization_code = secrets.token_urlsafe(24)
        consent.access_token = secrets.token_urlsafe(32)
        # SCA (PISP) : le code ne devient valable qu'après la preuve d'OTP (lab).
        if consent.role == ROLE_PISP and otp != "123456":
            consent.status = "PENDING"
            return {"authorised": False, "reason": "sca_failed"}
        return {
            "authorised": True,
            "consent_id": consent_id,
            "authorization_code": consent.authorization_code,
        }

    def exchange_code(self, consent_id: str, code: str) -> dict:
        consent = self._consents.get(consent_id)
        if not consent or consent.authorization_code != code:
            return {"error": "invalid_code"}
        if consent.status != "AUTHORISED":
            return {"error": "consent_not_authorised"}
        return {
            "access_token": consent.access_token,
            "token_type": "Bearer",
            "scope": f"openid payments:initiation" if consent.role == ROLE_PISP else "openid accounts:read",
            "expires_in": 900,
        }

    def initiate_payment(self, consent_id: str, access_token: str, amount: float, currency: str = "EUR") -> dict:
        consent = self._consents.get(consent_id)
        if not consent:
            return {"initiated": False, "reason": "unknown_consent"}
        if consent.status != "AUTHORISED":
            return {"initiated": False, "reason": "consent_not_authorised", "sca_required": True}
        if consent.access_token != access_token:
            return {"initiated": False, "reason": "invalid_token"}
        if consent.role != ROLE_PISP:
            return {"initiated": False, "reason": "role_not_pisp"}
        if consent.amount_limit and amount > consent.amount_limit:
            return {"initiated": False, "reason": "above_amount_limit"}
        return {
            "initiated": True,
            "payment_id": f"pisp_{secrets.token_hex(8)}",
            "consent_id": consent_id,
            "amount": amount,
            "currency": currency,
        }

    def revoke_consent(self, consent_id: str) -> dict:
        consent = self._consents.get(consent_id)
        if not consent:
            return {"revoked": False, "reason": "unknown_consent"}
        consent.status = "REVOKED"
        return {"revoked": True, "consent_id": consent_id}


SERVICE = OpenBankingService()