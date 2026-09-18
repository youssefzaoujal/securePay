"""HSM simulé — SoftHSM2/PKCS#11 avec repli logiciel (Phase 3).

Le contrat d'un HSM : la matière cryptographique (clés, KEK, CAVV/ARPC) reste
*dans* le HSM, jamais exposée en clair au process. L'app ne voit que des handles
et des résultats signés. Ici :
  - `SoftHSMBackend`  : vrai slot PKCS#11 via python-pkcs11 + libsofthsm2.so
  - `SoftwareHSM`     : repli mémoire, API identique (marque "lab substitute")
  - `HSM`             : façade qui choisit le backend dispo
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets

logger = logging.getLogger("securepay.hsm")


class HSMError(RuntimeError):
    pass


def _find_softhsm_lib() -> str | None:
    candidates = [
        os.getenv("SOFTHSM2_LIB"),
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "C:\\Program Files\\SoftHSM2\\lib\\softhsm2.dll",
        "C:\\SoftHSM2\\bin\\softhsm2.dll",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


class SoftwareHSM:
    """Backend mémoire : les clés ne sortent jamais — handle + sign seulement."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}

    def provision_key(self, algorithm: str = "AES256", purpose: str = "cavv") -> str:
        kid = f"key_{secrets.token_hex(8)}"
        self._keys[kid] = secrets.token_bytes(32 if algorithm == "AES256" else 16)
        return kid

    def sign(self, kid: str, data: bytes) -> bytes:
        if kid not in self._keys:
            raise HSMError("clé inconnue (ou clé non-extractible hors HSM)")
        return hmac.new(self._keys[kid], data, hashlib.sha256).digest()

    def sign_cavv(self, kid: str, value: str) -> str:
        # Ex.: HMAC-SHA256 tronquée à 21 octets → base64 (28 chars) comme en phase 1
        raw = self.sign(kid, value.encode())
        import base64

        return base64.b64encode(raw[:21]).decode()

    def verify(self, kid: str, data: bytes, expected: bytes) -> bool:
        return hmac.compare_digest(self.sign(kid, data), expected)

    def export_key(self, kid: str):
        raise HSMError("export de clé refusé: CKA_EXTRACTABLE=FALSE")

    def generate_kek(self) -> str:
        return self.provision_key("AES256", "kek")

    @staticmethod
    def is_available() -> bool:
        return True

    supports_verify = True


class SoftHSMBackend:
    """Backend PKCS#11 (python-pkcs11). Nécessite libsofthsm2 + token initialisé."""

    def __init__(self):
        lib_path = _find_softhsm_lib()
        if not lib_path:
            raise HSMError("libsofthsm2 introuvable — installez SoftHSM2 ou utilisez SoftwareHSM")
        try:
            import pkcs11  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise HSMError("python-pkcs11 non installé") from exc
        self._pkcs11 = pkcs11
        self._lib = pkcs11.lib(lib_path)
        self._token = None

    def _slot(self):
        if self._token is not None:
            return self._token
        slots = self._lib.get_slots(token_present=True)
        if not slots:
            raise HSMError("aucun slot SoftHSM avec token")
        token = slots[0].open_token()
        self._token = token
        return token

    def provision_key(self, algorithm: str = "AES256", purpose: str = "cavv") -> str:
        token = self._slot()
        with token.open(rw=True, user_pin=os.getenv("SOFTHSM_PIN", "1234")) as session:
            key = session.generate_key(
                self._pkcs11.KeyType.GENERIC_SECRET,
                256 if algorithm == "AES256" else 128,
                store=True,
                label=purpose,
                template=[
                    (self._pkcs11.Attribute.EXTRACTABLE, False),
                    (self._pkcs11.Attribute.SIGN, True),
                ],
            )
            return f"{purpose}:{key.object_class}"

    def sign(self, kid: str, data: bytes) -> bytes:
        token = self._slot()
        with token.open(rw=False, user_pin=os.getenv("SOFTHSM_PIN", "1234")) as session:
            keys = session.get_objects({self._pkcs11.Attribute.LABEL: "cavv"})
            if not keys:
                raise HSMError("aucune clé CAVV dans le HSM")
            mech = self._pkcs11.Mechanism.SHA256_HMAC
            return session.create_hmac(keys[0], mech, data)

    def sign_cavv(self, kid: str, value: str) -> str:
        return self.sign(kid, value.encode()).hex()

    def export_key(self, kid: str):
        raise HSMError("export refusé: CKA_EXTRACTABLE=FALSE")

    def generate_kek(self) -> str:
        return self.provision_key("AES256", "kek")

    @staticmethod
    def is_available() -> bool:
        return (_find_softhsm_lib() is not None) and _import_pkcs11_ok()


def _import_pkcs11_ok() -> bool:
    try:
        import pkcs11  # noqa: F401
        return True
    except Exception:
        return False


def get_hsm(backend: str = "auto") -> SoftwareHSM | SoftHSMBackend:
    if backend == "software":
        return SoftwareHSM()
    if SoftHSMBackend.is_available():
        try:
            return SoftHSMBackend()
        except Exception as exc:  # pragma: no cover
            logger.warning("HSM réaliste indisponible (%s) → SoftwareHSM", exc)
    return SoftwareHSM()