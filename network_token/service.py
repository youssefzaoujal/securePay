"""Network Tokenization — simulation type Visa VTS / Mastercard MDES (Phase 3).

Différence clé avec la tokenisation PAN interne (tokenization/coffre AES-GCM) :
le token réseau (`ntk_…`) est un **jeton d'usage** lié à un domaine (card scheme,
marchand/porte-monnaie) et protégé par cryptogram. Il ne dérive jamais vers le PAN
(sens unique), et son cycle de vie (activation, déactivation, remplacement) est géré
côté network. Ici : provision, authenticate (usage), deactivate, idempotence.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# Le PAN n'est JAMAIS stocké : on garde une empreinte déterministe (vault sim)
# pour la re-liason au coffre interne (tokenization/).

_PAN_DIGEST_KEY = b"network-token-vault-sim-key"  # en prod : HSM + Vault

PAN_NOMINAL = ("4111111111111111", "5500000000000004")


@dataclass
class NetworkToken:
    token_reference: str
    pan_hint: str               # "411111xxxxxx1111" — seule information persistée
    pan_digest: str
    domain: str                 # ex: "merchant-api.clicktopay"
    state: str = "ACTIVE"        # ACTIVE | SUSPENDED | DEACTIVATED
    cryptogram: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class NetworkTokenService:
    """Simulation VTS/MDES : provisions et usage de tokens réseau."""

    def __init__(self):
        self._tokens: dict[str, NetworkToken] = {}

    @staticmethod
    def _pan_digest(pan: str) -> str:
        return hmac.new(_PAN_DIGEST_KEY, pan.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _pan_hint(pan: str) -> str:
        return f"{pan[:6]}xxxxxx{pan[-4:]}" if len(pan) >= 10 else "****"

    @staticmethod
    def _cryptogram(secret: str, token: str) -> str:
        return base64_hmac(secret, token)[:16]

    def provision(self, pan: str, domain: str, idempotency_key: Optional[str] = None) -> dict:
        """PAN → token réseau. Idempotent : même clé → même token."""
        if idempotency_key:
            existing = [t for t in self._tokens.values() if t.pan_digest == self._pan_digest(pan) and t.domain == domain and t.created_at == idempotency_key]
            if existing:
                return self._describe(existing[0])

        if len(pan) not in (16, 18, 19) or not pan.isdigit():
            raise ValueError("PAN réseau invalide")
        token = NetworkToken(
            token_reference=f"ntk_{secrets.token_hex(10)}",
            pan_hint=self._pan_hint(pan),
            pan_digest=self._pan_digest(pan),
            domain=domain,
        )
        token.cryptogram = self._cryptogram(settings_nt_secret(), token.token_reference)
        self._tokens[token.token_reference] = token
        return self._describe(token)

    def authenticate(self, token_reference: str, cryptogram: str, domain: str) -> dict:
        """Usage d'un token réseau : le cryptogram + domaine doivent matcher."""
        token = self._tokens.get(token_reference)
        if not token or token.state != "ACTIVE":
            return {"authenticated": False, "reason": "token_not_active"}
        if token.domain != domain:
            return {"authenticated": False, "reason": "domain_binding_mismatch"}
        expected = self._cryptogram(settings_nt_secret(), token_reference)
        if not hmac.compare_digest(cryptogram, expected):
            return {"authenticated": False, "reason": "cryptogram_invalid"}
        return {"authenticated": True, "token_reference": token_reference, "domain": domain}

    def deactivate(self, token_reference: str) -> dict:
        token = self._tokens.get(token_reference)
        if not token:
            return {"deactivated": False, "reason": "unknown_token"}
        token.state = "DEACTIVATED"
        return {"deactivated": True, "token_reference": token_reference}

    def status(self, token_reference: str) -> dict:
        token = self._tokens.get(token_reference)
        if not token:
            return {"exists": False}
        return {"exists": True, **self._describe(token)}

    def _describe(self, token: NetworkToken) -> dict:
        return {
            "token_reference": token.token_reference,
            "pan_hint": token.pan_hint,
            "domain": token.domain,
            "state": token.state,
            "cryptogram": token.cryptogram,
            "created_at": token.created_at,
        }


def settings_nt_secret() -> str:
    from config import get_settings

    secret = get_settings().NETWORK_TOKEN_VAULT_PATH or "dev-net-token-secret"
    return f"nt-vault:{secret}"


def base64_hmac(secret: str, value: str) -> str:
    import base64

    return base64.b64encode(hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()).decode()


SERVICE = NetworkTokenService()