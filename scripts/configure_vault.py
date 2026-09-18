#!/usr/bin/env python3
"""Provisionne Vault en mode dynamique pour SecurePay (lab).

Active les secrets engines manquants et crée les rôles utilisés par le code :
  - database : creds PostgreSQL dynamiques (secret de courte durée, rotation auto)
  - pki      : issuance de certificats mTLS internes (service-to-service)

Usage :
    python -m scripts.configure_vault          # Vault réel (VAULT_TOKEN requis)
    python -m scripts.configure_vault --dev    # DevVaultClient (mémoire, aucune action) — teste les contrats

Exemple (container dev) :
    docker compose up -d vault
    $env:VAULT_TOKEN = "lab-root-token"
    python -m scripts.configure_vault
"""

from __future__ import annotations

import argparse
import os
import sys

from config import get_settings
from vault_integration.client import VaultBackendError, VaultClient, DevVaultClient

settings = get_settings()


def configure_real_vault() -> int:
    try:
        vault = VaultClient()
    except VaultBackendError as exc:
        print(f"[vault] {exc} — lancez `docker compose up -d vault` et VAULT_TOKEN")
        return 1

    # Heads-up : les engines suivants sont idempotents en dev-root.
    try:
        vault.client.sys.enable_secrets_engine(backend_type="database", path="database")
        print("[vault] database engine activé")
    except Exception:
        print("[vault] database engine déjà actif")

    try:
        vault.client.sys.enable_secrets_engine(backend_type="pki", path="pki")
        print("[vault] pki engine activé")
    except Exception:
        print("[vault] pki engine déjà actif")

    # PKI : CA racine de lab + rôle d'issuance.
    try:
        vault.client.secrets.pki.create_root(payload={"common_name": "securepay.lab CA", "ttl": "8760h", "key_type": "rsa", "key_bits": 2048})
        print("[vault] CA racine créée")
    except Exception:
        print("[vault] CA racine déjà présente via %s", vault.client.sys.read_root_ca if hasattr(vault.client.sys, "read_root_ca") else "")
        try:
            vault.client.secrets.pki.tune(mount_point="pki", max_lease_ttl="8760h")
        except Exception:
            pass

    try:
        vault.client.secrets.pki.create_or_update_role(
            name=settings.VAULT_PKI_ROLE,
            mount_point=settings.VAULT_PKI_MOUNT,
            role={"allowed_domains": "svc", "allow_subdomains": True, "max_ttl": "720h"},
        )
        print(f"[vault] rôle PKI {settings.VAULT_PKI_ROLE} prêt")
    except Exception as exc:
        print(f"[vault] rôle PKI : {exc}")

    # Database : connection PostgreSQL + rôle géré (lab postgres root obtenu depuis .env).
    import os as _os

    pg_user = _os.getenv("POSTGRES_PASSWORD") or "securepay_dev"
    db_conn = {
        "plugin_name": "postgresql-database-plugin",
        "allowed_roles": [settings.VAULT_DB_ROLE],
        "connection_url": "postgresql://{{username}}:{{password}}@postgres:5432/securepay",
        "username": "securepay",
        "password": pg_user,
        "name": "securepay-lab-pg",
    }
    try:
        vault.client.secrets.database.configure(
            name=db_conn["name"],
            plugin_name=db_conn["plugin_name"],
            allowed_roles=db_conn["allowed_roles"],
            connection_url=db_conn["connection_url"],
            username=db_conn["username"],
            password=db_conn["password"],
        )
        print("[vault] connexion PostgreSQL enregistrée")
    except Exception as exc:
        print(f"[vault] connexion PG : {exc}")

    try:
        vault.client.secrets.database.create_role(
            name=settings.VAULT_DB_ROLE,
            db_name=db_conn["name"],
            default_ttl="15m",
            max_ttl="24h",
            creation_statements=['GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";'],
        )
        print(f"[vault] rôle DB {settings.VAULT_DB_ROLE} prêt (TTL 15m)")
    except Exception as exc:
        print(f"[vault] rôle DB : {exc}")

    print("[vault] OK — creds court-terme + PKI disponibles")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", action="store_true", help="teste les contrats sans Vault")
    args = parser.parse_args()

    if args.dev:
        vault = DevVaultClient()
        creds = vault.get_db_credentials()
        cert = vault.issue_pki_cert("fraud.svc")
        assert creds["username"].startswith("sp_"), "contrat creds dynamiques"
        assert "PRIVATE KEY" in cert["private_key"], "contrat PKI"
        print(f"[vault-dev] creds dynamiques OK ({creds['username']}, ttl={creds['ttl']}s)")
        print(f"[vault-dev] PKI OK (serial={cert['serial_number']})")
        return 0

    return configure_real_vault()


if __name__ == "__main__":
    sys.exit(main())