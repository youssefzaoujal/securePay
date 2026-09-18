"""Tests Open Banking PSD2 (Phase 3) — consent, code flow, SCA PISP, role gating."""

from __future__ import annotations

import pytest

from openbanking.service import OpenBankingService


@pytest.fixture
def bank():
    return OpenBankingService()


def test_request_consent_aisp(bank):
    res = bank.request_consent("aisp", "Acme Analytics")
    assert res["consent_id"].startswith("csnt_")
    assert res["redirect_uri"].startswith("/openbanking/authorize?consent_id=")
    assert res["status"] == "PENDING"


def test_request_consent_rejects_unknown_role(bank):
    with pytest.raises(ValueError):
        bank.request_consent("merchant", "x")


def test_authorize_issues_code_and_token(bank):
    consent = bank.request_consent("aisp", "TPP", ["FR761234567"])
    out = bank.authorize(consent["consent_id"])
    assert out["authorised"] is True
    stored = bank._consents[consent["consent_id"]]
    assert stored.status == "AUTHORISED"
    assert stored.access_token


def test_exchange_code(bank):
    consent = bank.request_consent("pisp", "TPP Pay")
    auth = bank.authorize(consent["consent_id"])
    token = bank.exchange_code(consent["consent_id"], auth["authorization_code"])
    assert token["access_token"]
    assert "payments:initiation" in token["scope"]


def test_exchange_bad_code_fails(bank):
    assert bank.exchange_code("none", "bad")["error"] == "invalid_code"


def test_pisp_requires_authorised_consent(bank):
    consent = bank.request_consent("pisp", "TPP Pay")
    res = bank.initiate_payment(consent["consent_id"], "tok", 100.0)
    assert res["initiated"] is False
    assert res["sca_required"] is True


def test_initiate_payment_success(bank):
    consent = bank.request_consent("pisp", "TPP Pay", amount_limit=2000)
    auth = bank.authorize(consent["consent_id"])
    token = bank.exchange_code(consent["consent_id"], auth["authorization_code"])
    res = bank.initiate_payment(consent["consent_id"], token["access_token"], 150.0)
    assert res["initiated"] is True
    assert res["payment_id"].startswith("pisp_")


def test_initiate_above_amount_limit_rejected(bank):
    consent = bank.request_consent("pisp", "TPP Pay", amount_limit=100)
    auth = bank.authorize(consent["consent_id"])
    token = bank.exchange_code(consent["consent_id"], auth["authorization_code"])
    res = bank.initiate_payment(consent["consent_id"], token["access_token"], 999.0)
    assert res["initiated"] is False
    assert res["reason"] == "above_amount_limit"


def test_aisp_cannot_initiate_payment(bank):
    consent = bank.request_consent("aisp", "Acme Read")
    auth = bank.authorize(consent["consent_id"])
    token = bank.exchange_code(consent["consent_id"], auth["authorization_code"])
    res = bank.initiate_payment(consent["consent_id"], token["access_token"], 1.0)
    assert res["initiated"] is False
    assert res["reason"] == "role_not_pisp"


def test_sca_otp_failure_blocks_pisp(bank):
    consent = bank.request_consent("pisp", "TPP Pay")
    out = bank.authorize(consent["consent_id"], otp="000000")
    assert out["authorised"] is False
    assert out["reason"] == "sca_failed"
    assert bank._consents[consent["consent_id"]].status == "PENDING"


def test_revoke_blocks_payment(bank):
    consent = bank.request_consent("pisp", "TPP", amount_limit=500)
    auth = bank.authorize(consent["consent_id"])
    token = bank.exchange_code(consent["consent_id"], auth["authorization_code"])
    bank.revoke_consent(consent["consent_id"])
    res = bank.initiate_payment(consent["consent_id"], token["access_token"], 10.0)
    assert res["initiated"] is False