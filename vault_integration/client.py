"""Intégration HashiCorp Vault — secrets dynamiques (Phase 2).

Pas juste un coffre : les credentials deviennent *rotatifs* et *éphémères*.
  - `get_db_credentials()` : creds PostgreSQL dynamiques (database secrets engine),
    TTL court, révoqués automatiquement — aucun secret en dur dans le code.
  - `issue_pki_cert()` : certificats mTLS internes (PKI secrets engine) pour le
    grille de service-to-service.
  - Repli `DevVaultClient` quand hvac absent / pas de Vault (tests, lab minimal).

Usage :
    vault = VaultClient()
    creds = vault.get_db_credentials(settings.VAULT_DB_ROLE)   # {"username","password","ttl"}
    cert, key, ca = vault.issue_pki_cert("payment.securepay.svc")
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from config import get_settings

logger = logging.getLogger("securepay.vault")
settings = get_settings()

try:
    import hvac  # type: ignore
    HAVE_HVAC = True
except Exception:  # pragma: no cover
    hvac = None  # type: ignore
    HAVE_HVAC = False


class VaultBackendError(RuntimeError):
    pass


class _VaultClientBase:
    """Interface commune (Vault réel + repli dev)."""

    def get_db_credentials(self, role: str | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def issue_pki_cert(self, common_name: str, ttl: str = "24h") -> dict[str, str]:
        raise NotImplementedError

    def read_kv(self, path: str) -> Optional[dict]:
        raise NotImplementedError

    def write_kv(self, path: str, data: dict) -> None:
        raise NotImplementedError

    def revoke_leased_credentials(self, lease_id: str) -> None:
        raise NotImplementedError


class VaultClient(_VaultClientBase):
    """Client Vault réel (hvac) → dynamic secrets, PKI, KV v2."""

    def __init__(self, url: str | None = None, token: str | None = None):
        self.url = url or settings.VAULT_URL
        self.token = token or settings.VAULT_TOKEN or os.getenv("VAULT_TOKEN", "")
        if not HAVE_HVAC:
            raise VaultBackendError("hvac non installé — utilisez DevVaultClient")
        if not self.token:
            raise VaultBackendError("VAULT_TOKEN requis pour VaultClient")
        self.client = hvac.Client(url=self.url, token=self.token)
        if not self.client.is_authenticated():
            raise VaultBackendError("Authentification Vault refusée")

    def get_db_credentials(self, role: str | None = None) -> dict[str, Any]:
        role = role or settings.VAULT_DB_ROLE
        resp = self.client.secrets.database.generate_credentials(name=role)
        data = resp.get("data", {})
        return {
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "lease_id": resp.get("lease_id"),
            "lease_duration": resp.get("lease_duration"),
        }

    def issue_pki_cert(self, common_name: str, ttl: str = "24h") -> dict[str, str]:
        resp = self.client.secrets.pki.generate_certificate(
            name=settings.VAULT_PKI_ROLE,
            common_name=common_name,
            ttl=ttl,
        )
        data = resp.get("data", {})
        return {
            "certificate": data["certificate"],
            "private_key": data.get("private_key", ""),
            "issuing_ca": data.get("issuing_ca", ""),
            "serial_number": data.get("serial_number", ""),
        }

    def read_kv(self, path: str) -> Optional[dict]:
        try:
            resp = self.client.secrets.kv.v2.read_secret_version(path=path, mount_point="secret")
            return resp.get("data", {}).get("data", {})
        except Exception:  # noqa: BLE001
            return None

    def write_kv(self, path: str, data: dict) -> None:
        self.client.secrets.kv.v2.create_or_update_secret(path=path, secret=data, mount_point="secret")

    def revoke_leased_credentials(self, lease_id: str) -> None:
        self.client.sys.revoke_lease(lease_id=lease_id)


class DevVaultClient(_VaultClientBase):
    """Repli sans Vault : mêmes contrats, mémoire + fichiers PEM.

    Permet de (a) tester sans broker et (b) démontrer le workflow dynamique avec
    une simulation nette. Documenté comme 'lab substitute'.
    """

    def __init__(self):
        self._db_slots: dict[str, list[dict]] = {}
        self._kv: dict[str, dict] = {}
        self._serial = 0

    def get_db_credentials(self, role: str | None = None) -> dict[str, Any]:
        role = role or settings.VAULT_DB_ROLE
        import secrets as _sec
        import string

        username = f"sp_{_sec.token_hex(6)}_ro"
        password = "".join(_sec.choice(string.ascii_letters + string.digits) for _ in range(24))
        self._serial += 1
        lease_id = f"{role}/lease/{self._serial}"
        slot = {"username": username, "password": password, "lease_id": lease_id, "ttl": 900}
        self._db_slots.setdefault(role, []).append(slot)
        return dict(slot)

    def issue_pki_cert(self, common_name: str, ttl: str = "24h") -> dict[str, str]:
        # Cert auto-signé (lab) pour démontrer le contrat PKI — pas un vrai CA.
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        self._serial += 1
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(self._serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(hours=24))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        return {
            "certificate": pem,
            "private_key": key_pem,
            "issuing_ca": pem,
            "serial_number": f"{self._serial:016x}",
        }

    def read_kv(self, path: str) -> Optional[dict]:
        return self._kv.get(path)

    def write_kv(self, path: str, data: dict) -> None:
        self._kv[path] = dict(data)

    def revoke_leased_credentials(self, lease_id: str) -> None:
        for role, slots in self._db_slots.items():
            self._db_slots[role] = [s for s in slots if s.get("lease_id") != lease_id]


def get_vault() -> _VaultClientBase:
    """Retourne Vault réel si dispo, sinon DevVault (lab)."""
    try:
        return VaultClient()
    except Exception:  # noqa: BLE001 — tout défaut de connexion → repli dev
        logger.info("Vault indisponible → DevVaultClient (mémoire)")
        return DevVaultClient()