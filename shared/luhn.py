"""Validation Luhn + BIN — cartes de test uniquement (simulation)."""

from __future__ import annotations


TEST_PANS = {
    "4111111111111111": "visa",
    "4000000000000002": "visa",
    "5555555555554444": "mastercard",
    "5105105105105100": "mastercard",
    "378282246310005": "amex",
    "371449635398431": "amex",
}


def luhn_ok(pan: str) -> bool:
    digits = [int(ch) for ch in pan if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def detect_brand(pan: str) -> str:
    if pan in TEST_PANS:
        return TEST_PANS[pan]
    prefixes = (
        ("6011", "discover"),
        ("34", "amex"),
        ("37", "amex"),
        ("35", "jcb"),
        ("5", "mastercard"),
        ("4", "visa"),
    )
    for prefix, brand in prefixes:
        if pan.startswith(prefix):
            return brand
    return "unknown"
