"""Luhn + BIN — cartes de test uniquement."""

from shared.luhn import detect_brand, luhn_ok


def test_visa_test_pan():
    assert luhn_ok("4111111111111111")
    assert detect_brand("4111111111111111") == "visa"


def test_rejects_short_pan():
    assert not luhn_ok("41111")
