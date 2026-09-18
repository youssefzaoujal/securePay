"""Tests intégration Vault dynamique (Phase 2) — contrats creds rotatifs + PKI."""

from __future__ import annotations

import pytest

from vault_integration.client import DevVaultClient


@pytest.fixture
def vault():
    return DevVaultClient()


def test_db_credentials_rotated_per_call(vault):
    a = vault.get_db_credentials("sp-role")
    b = vault.get_db_credentials("sp-role")
    assert a["username"] != b["username"]
    assert a["password"] != b["password"]
    assert a["lease_id"] != b["lease_id"]
    assert a["ttl"] > 0


def test_db_credentials_marked_slot(vault):
    creds = vault.get_db_credentials("sp-role")
    assert creds["lease_id"].startswith("sp-role/lease/")


def test_revoke_removes_slot(vault):
    a = vault.get_db_credentials("sp-role")
    vault.revoke_leased_credentials(a["lease_id"])
    remaining = [slot["lease_id"] for slot in vault._db_slots.get("sp-role", [])]
    assert a["lease_id"] not in remaining


def test_pki_cert_is_real_pem(vault):
    out = vault.issue_pki_cert("fraud.svc")
    assert "BEGIN CERTIFICATE" in out["certificate"]
    assert "BEGIN PRIVATE KEY" in out["private_key"]
    assert out["issuing_ca"]
    assert len(out["serial_number"]) == 16


def test_pki_cert_has_expected_cn(vault):
    from cryptography import x509

    out = vault.issue_pki_cert("payment.securepay.svc")
    cert = x509.load_pem_x509_certificate(out["certificate"].encode())
    assert cert.subject.rfc4514_string().endswith("payment.securepay.svc")


def test_kv_roundtrip(vault):
    vault.write_kv("secret/securepay/network-token", {"key": "abc"})
    assert vault.read_kv("secret/securepay/network-token") == {"key": "abc"}


def test_get_vault_factory_returns_dev_without_vault(monkeypatch):
    monkeypatch.setenv("VAULT_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("VAULT_TOKEN", "")
    from vault_integration.client import get_vault

    assert isinstance(get_vault(), DevVaultClient)