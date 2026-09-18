"""Tests network tokenization (Phase 3) — provision, idempotence, usage, cycle de vie."""

from __future__ import annotations

import pytest

from network_token.service import NetworkTokenService, PAN_NOMINAL


@pytest.fixture
def svc():
    return NetworkTokenService()


def test_provision_generates_network_token(svc):
    out = svc.provision(PAN_NOMINAL[0], "merchant-api.clicktopay")
    assert out["token_reference"].startswith("ntk_")
    assert out["cryptogram"]
    assert "111111" not in out["pan_hint"] or out["pan_hint"].endswith("1111")


def test_pan_never_stored(svc):
    out = svc.provision("4111111111111111", "d")
    token = svc._tokens[out["token_reference"]]
    # Seule l'empreinte + hint survive — pas le PAN.
    assert token.pan_digest != "4111111111111111"
    assert not hasattr(token, "pan")


def test_provision_rejects_bad_pan(svc):
    with pytest.raises(ValueError):
        svc.provision("1234", "d")


def test_authenticate_valid_cryptogram(svc):
    prov = svc.provision(PAN_NOMINAL[1], "merchant-api.clicktopay")
    out = svc.authenticate(prov["token_reference"], prov["cryptogram"], "merchant-api.clicktopay")
    assert out["authenticated"] is True


def test_authenticate_fails_wrong_cryptogram(svc):
    prov = svc.provision(PAN_NOMINAL[1], "d")
    out = svc.authenticate(prov["token_reference"], "wrong", "d")
    assert out["authenticated"] is False
    assert out["reason"] == "cryptogram_invalid"


def test_authenticate_domain_binding(svc):
    prov = svc.provision(PAN_NOMINAL[1], "merchant-api.clicktopay")
    out = svc.authenticate(prov["token_reference"], prov["cryptogram"], "another-domain.com")
    assert out["authenticated"] is False
    assert out["reason"] == "domain_binding_mismatch"


def test_deactivate_blocks_usage(svc):
    prov = svc.provision(PAN_NOMINAL[0], "d")
    assert svc.deactivate(prov["token_reference"])["deactivated"]
    out = svc.authenticate(prov["token_reference"], prov["cryptogram"], "d")
    assert out["authenticated"] is False


def test_status_unknown(svc):
    assert svc.status("ntk_unknown") == {"exists": False}