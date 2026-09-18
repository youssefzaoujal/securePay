"""HMAC webhooks — authenticité + anti-replay."""

import time

from shared.webhooks import sign_payload, verify_signature


def test_hmac_roundtrip():
    payload = {"type": "payment.succeeded", "payment_id": "pay_1", "amount": 42.0}
    ts, sig = sign_payload(payload)
    assert verify_signature(payload, ts, sig)


def test_hmac_rejects_tamper():
    payload = {"type": "payment.succeeded", "amount": 42.0}
    ts, sig = sign_payload(payload)
    assert not verify_signature({"type": "payment.succeeded", "amount": 99.0}, ts, sig)


def test_hmac_rejects_stale_timestamp():
    payload = {"type": "payment.succeeded"}
    ts, sig = sign_payload(payload, timestamp=int(time.time()) - 10_000)
    assert not verify_signature(payload, ts, sig, max_age=300)
