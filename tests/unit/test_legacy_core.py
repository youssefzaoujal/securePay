"""Sanitize + fallback métier du core COBOL (sans gnucobol sur Windows)."""

import pytest
from fastapi.testclient import TestClient

from legacy_core.sanitize import (
    LegacyInputError,
    account_from_merchant,
    cents,
    validate_account_id,
    validate_amount,
)


def test_account_from_merchant_strips_injection():
    assert account_from_merchant("merchant-api") == "MERCHANTAP"
    with pytest.raises(LegacyInputError):
        validate_account_id("ABC; rm -rf /")
    with pytest.raises(LegacyInputError):
        validate_account_id("../../etc/passwd")
    with pytest.raises(LegacyInputError):
        validate_account_id("$(whoami)")


def test_amount_and_cents_are_digits_only():
    assert cents(12.34) == "1234"
    assert validate_amount(500000) == 500000.0
    with pytest.raises(LegacyInputError):
        validate_amount(-1)
    with pytest.raises(LegacyInputError):
        validate_amount(float("nan"))


def test_fallback_decide(monkeypatch):
    monkeypatch.setenv("LEGACY_CORE_ALLOW_FALLBACK", "1")
    monkeypatch.delenv("LEGACY_COBOL_BIN", raising=False)
    from legacy_core.cobol_runner import decide

    monkeypatch.setattr("legacy_core.cobol_runner.binary_path", lambda: __import__("pathlib").Path("/no/such/validate"))
    assert decide("MERCHANT01", 100) == "APPROVED"
    assert decide("MERCHANT01", 600000) == "DECLINED"


def test_wrapper_rejects_bad_account(monkeypatch, tmp_path):
    monkeypatch.setenv("LEGACY_CORE_ALLOW_FALLBACK", "1")
    monkeypatch.setenv("SECUREPAY_EVENT_LOG", str(tmp_path / "events.jsonl"))
    from legacy_core.cobol_runner import decide as real_decide
    import legacy_core.wrapper as wrapper

    monkeypatch.setattr(wrapper, "decide", lambda account, amount: real_decide(account, amount))
    monkeypatch.setattr(
        "legacy_core.cobol_runner.binary_path",
        lambda: __import__("pathlib").Path("/no/such/validate"),
    )
    client = TestClient(wrapper.app)
    denied = client.post("/validate", json={"account_id": "x;id", "amount": 10})
    assert denied.status_code == 400
    ok = client.post("/validate", json={"merchant_id": "merchant-api", "amount": 99})
    assert ok.status_code == 200
    assert ok.json()["status"] == "APPROVED"
    big = client.post("/validate", json={"account_id": "MERCHANT01", "amount": 600000})
    assert big.json()["status"] == "DECLINED"
