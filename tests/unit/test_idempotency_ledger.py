"""Idempotence capture + grand livre."""

import pytest

from payment.idempotency import IdempotencyConflict, IdempotencyStore
from payment.ledger import Ledger


def test_idempotency_replay_same_payload():
    store = IdempotencyStore()
    payload = {"amount": 10.0, "currency": "EUR", "card_token": "tok_a", "merchant_id": "m1"}
    assert store.replay_or_conflict("m1", "key-1", payload) is None
    store.remember("m1", "key-1", payload, "pay_aaa")
    assert store.replay_or_conflict("m1", "key-1", payload) == "pay_aaa"


def test_idempotency_conflict_different_payload():
    store = IdempotencyStore()
    store.remember("m1", "key-1", {"amount": 10.0}, "pay_aaa")
    with pytest.raises(IdempotencyConflict):
        store.replay_or_conflict("m1", "key-1", {"amount": 99.0})


def test_ledger_double_entry_reconciles():
    ledger = Ledger()
    ledger.post_capture("pay_1", "merchant-api", 42.5, "EUR")
    ledger.post_capture("pay_1", "merchant-api", 42.5, "EUR")  # idempotent
    report = ledger.reconcile()
    assert report["balanced"] is True
    assert report["captures"] == 1
    assert report["entries"] == 2
    assert ledger.balance() == 0.0


def test_ledger_detects_unbalanced_tamper():
    ledger = Ledger()
    ledger.post_capture("pay_2", "m1", 10, "EUR")
    from payment.ledger import Entry

    ledger.entries.append(Entry("assets:scheme_receivable", "debit", 5, "EUR", "tamper", "now"))
    assert ledger.reconcile()["balanced"] is False
