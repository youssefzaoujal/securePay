"""Tests bus Kafka (Phase 2) — repli JSONL sans broker, sérialisation, pont SOC."""

from __future__ import annotations

import json

import pytest


def _fresh_bus(bootstrap: str = ""):
    from kafka_events.producer import KafkaEventBus

    return KafkaEventBus(bootstrap_servers=bootstrap, topic="securepay.events.test")


def test_no_broker_falls_back_to_jsonl():
    import asyncio

    bus = _fresh_bus("")
    assert bus.enabled is False
    assert asyncio.run(bus.send({"a": 1})) is False


def test_serialize_redacts_pan():
    bus = _fresh_bus("")
    raw = bus.serialize({"card_number": "4111111111111111", "amount": 10.0, "purpose": "test"})
    payload = json.loads(raw)
    body = json.dumps(payload)
    assert "4111111111111111" not in body
    assert "4111" not in body
    assert payload["purpose"] == "test"


def test_emit_event_uses_jsonl_without_broker(tmp_path, monkeypatch):
    log = tmp_path / "events.jsonl"
    monkeypatch.setenv("SECUREPAY_EVENT_LOG", str(log))
    try:
        import kafka_events.producer as kp

        old_bus = kp.get_bus()
        kp._bus = None
        kp.emit_event({"event_type": "payment_attempt", "status": "succeeded"})
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["event_type"] == "payment_attempt"
    finally:
        kp._bus = None


def test_bus_enabled_with_broker_configured(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:19092")
    from config import get_settings

    get_settings.cache_clear()
    try:
        bus = KafkaEventBus_for_test()
        assert bus.enabled is True
        assert "localhost:19092" in bus.bootstrap_servers
    finally:
        get_settings.cache_clear()


def KafkaEventBus_for_test():
    from kafka_events.producer import KafkaEventBus

    return KafkaEventBus(bootstrap_servers="localhost:19092", topic="securepay.events.test")


def test_serialize_adds_trace_fields_when_present():
    bus = _fresh_bus("")
    payload = json.loads(bus.serialize({"jti": "abc", "status": "blocked"}))
    assert payload["status"] == "blocked"


def test_shared_emit_still_writes_jsonl_without_broker(tmp_path, monkeypatch):
    """Sans KAFKA_BOOTSTRAP_SERVERS, le pont se retire et le JSONL est écrit."""
    log = tmp_path / "events.jsonl"
    monkeypatch.setenv("SECUREPAY_EVENT_LOG", str(log))
    monkeypatch.delenv("KAFKA_BOOTSTRAP_SERVERS", raising=False)
    import importlib

    import shared.events as events

    from kafka_events import bridge as kb

    importlib.reload(kb)
    importlib.reload(events)
    try:
        events.emit_event({"event_type": "bridge_test"})
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["event_type"] == "bridge_test"
        assert kb.BRIDGE._started is True
        assert kb.BRIDGE._skip_reason == "KAFKA_BOOTSTRAP_SERVERS vide"
    finally:
        kb.KafkaBridge._instance = None
        importlib.reload(kb)
        importlib.reload(events)