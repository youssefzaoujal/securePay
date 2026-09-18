"""Démo HSM (Phase 3) — provisioning, signature CAVV, non-extractabilité.

Usage:
    python -m scripts.hsm_demo
    python -m scripts.hsm_demo --backend softhsm   # si SoftHSM2 est présent
"""

from __future__ import annotations

import argparse

from hsm.service import HSMError, get_hsm


def run(backend: str = "auto") -> None:
    hsm = get_hsm(backend=backend)
    print(f"[hsm] backend actif : {type(hsm).__name__}")

    kid = hsm.provision_key(purpose="cavv")
    print(f"[hsm] cle CAVV provisionnée : {kid} (non extractible)")

    message = "3DSMessage|trans_123|amount=99.99"
    cavv = hsm.sign_cavv(kid, message)
    assert len(cavv) == 28, "CAVV attendu : 21 octets -> base64"
    print(f"[hsm] CAVV signe (HMAC-SHA256 tronque 21B) : {cavv}")

    verify = hsm.supports_verify and hsm.verify(kid, message.encode(), hsm.sign(kid, message.encode()))
    print(f"[hsm] verification HMAC : {'OK' if verify else 'n/a'}")

    kek = hsm.generate_kek()
    print(f"[hsm] KEK generee : {kek}")

    try:
        hsm.export_key(kid)
    except HSMError as exc:
        print(f"[hsm] export refuse (attendu) : {exc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", default="auto", choices=["auto", "softhsm", "software"])
    args = parser.parse_args()
    run(args.backend)