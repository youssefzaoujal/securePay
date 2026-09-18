"""Tests unitaires - Payment schemas."""

import pytest
from payment.schemas import ProcessPaymentRequest, PaymentStatus


class TestPaymentSchemas:
    """Tests pour les schémas Pydantic du service Payment."""

    def test_valid_payment_request(self):
        req = ProcessPaymentRequest(
            amount=99.99,
            currency="EUR",
            card_token="tok_abc123",
            merchant_id="MERCH_001",
        )
        assert req.amount == 99.99
        assert req.currency == "EUR"

    def test_payment_request_default_currency(self):
        req = ProcessPaymentRequest(
            amount=10.0,
            card_token="tok_abc123",
            merchant_id="MERCH_001",
        )
        assert req.currency == "EUR"

    def test_payment_request_negative_amount_fails(self):
        with pytest.raises(Exception):
            ProcessPaymentRequest(
                amount=-1.0,
                card_token="tok_abc123",
                merchant_id="MERCH_001",
            )

    def test_payment_status_enum(self):
        assert PaymentStatus.PENDING == "pending"
        assert PaymentStatus.SUCCEEDED == "succeeded"
        assert PaymentStatus.CHALLENGE_REQUIRED == "challenge_required"
        assert PaymentStatus.FAILED == "failed"
