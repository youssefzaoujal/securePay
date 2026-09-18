"""Coffre cryptographique AES-256-GCM — PCI-DSS Req 3.4 / 3.5.

Le CVV n'est JAMAIS chiffré ni persisté (Req 3.2.2) : il ne traverse
le service de tokenisation que le temps de l'autorisation simulée.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _load_key() -> bytes:
    raw = os.environ.get("VAULT_MASTER_KEY") or os.environ.get("SECUREPAY_VAULT_KEY")
    if raw:
        try:
            key = bytes.fromhex(raw)
            if len(key) == 32:
                return key
        except ValueError:
            encoded = raw.encode()
            if len(encoded) == 32:
                return encoded
    # Lab only — never use a static key in production (inject via Vault).
    lab_key = os.environ.get("APP_ENV", "lab")
    if lab_key == "lab":
        return hashlib_lab_key()
    raise RuntimeError("VAULT_MASTER_KEY (32 bytes hex) requis hors lab")


def hashlib_lab_key() -> bytes:
    # Deterministic lab key so containers share the vault without a secret store.
    # Documented as UNSAFE for production.
    return bytes.fromhex("a" * 64)


@lru_cache
def _aesgcm() -> AESGCM:
    return AESGCM(_load_key())


def encrypt_bytes(plaintext: str, aad: bytes = b"securepay-vault") -> bytes:
    nonce = secrets.token_bytes(12)
    ct = _aesgcm().encrypt(nonce, plaintext.encode(), aad)
    return nonce + ct


def decrypt_bytes(blob: bytes, aad: bytes = b"securepay-vault") -> str:
    nonce, ct = blob[:12], blob[12:]
    return _aesgcm().decrypt(nonce, ct, aad).decode()


def encrypt_card(card_number: str, card_expiry: str, card_cvv: str | None = None) -> dict:
    """Chiffre PAN + expiry. `card_cvv` est accepté puis IGNORÉ (jamais stocké)."""
    del card_cvv  # PCI-DSS Req 3.2.2 — SAD after authorization
    return {
        "encrypted_pan": encrypt_bytes(card_number).hex(),
        "encrypted_expiry": encrypt_bytes(card_expiry).hex(),
        "cvv_stored": False,
        "algorithm": "AES-256-GCM",
    }


def decrypt_token(encrypted_data: dict) -> dict:
    pan = decrypt_bytes(bytes.fromhex(encrypted_data["encrypted_pan"]))
    expiry = decrypt_bytes(bytes.fromhex(encrypted_data["encrypted_expiry"]))
    return {
        "card_number": pan,
        "card_expiry": expiry,
        "card_cvv": None,
    }
