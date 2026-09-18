"""Rédaction PCI — PAN / CVV / Bearer absents des logs."""

from shared.redaction import redact_secrets


def test_redacts_pan_in_nested_payload():
    payload = {
        "card_number": "4111111111111111",
        "card_cvv": "123",
        "authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.aaa.bbb",
        "nested": {"password": "super-secret", "note": "pay with 4111111111111111"},
    }
    redacted = redact_secrets(payload)
    blob = str(redacted)
    assert "4111111111111111" not in blob
    assert "123" not in str(redacted["card_cvv"])
    assert redacted["card_cvv"] == "***"
    assert "super-secret" not in blob
    assert "eyJhbGciOiJSUzI1NiJ9" not in blob
    assert redacted["card_number"].endswith("1111")
