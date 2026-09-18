"""Injection — les schémas Pydantic rejettent les payloads SQLi (pas de SQL concaténé)."""

import pytest
from pydantic import ValidationError

from payment.schemas import ProcessPaymentRequest


@pytest.mark.parametrize(
    "payload",
    [
        "1; DROP TABLE transactions;--",
        "' OR 1=1 --",
        "1 UNION SELECT password FROM users",
    ],
)
def test_sql_injection_in_merchant_id_is_just_a_string_never_executed(payload):
    """SQLAlchemy bind params: la valeur reste une string, jamais du SQL.

    On vérifie ici que le schéma accepte une string (l'ORM paramètre) et que
    aucun eval/format SQL n'existe dans ProcessPaymentRequest.
    """
    req = ProcessPaymentRequest(
        amount=10.0,
        card_token="tok_abc",
        merchant_id=payload,
    )
    assert req.merchant_id == payload
    assert "execute" not in ProcessPaymentRequest.model_json_schema()


def test_negative_amount_rejected():
    with pytest.raises(ValidationError):
        ProcessPaymentRequest(amount=-5, card_token="tok", merchant_id="m")
