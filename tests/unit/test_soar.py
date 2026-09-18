"""SOAR — auto-block sur alerte carding."""

from detection.engine.sigma_engine import SigmaEngine
from detection.soar.blocklist import is_blocked, list_blocks, unblock_ip
from detection.soar.responder import auto_respond


def test_auto_block_after_carding_threshold(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREPAY_BLOCKSTATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("SECUREPAY_BLOCKLIST", str(tmp_path / "blocks.jsonl"))
    engine = SigmaEngine("detection/sigma/rules")
    ip = "198.51.100.66"
    last = None
    for _ in range(10):
        last = engine.evaluate_event(
            {
                "event_type": "payment_attempt",
                "status": "failed",
                "source_ip": ip,
                "merchant_id": "merchant-api",
            }
        )
    assert last
    for alert in last:
        auto_respond(alert)
    assert is_blocked(ip)
    assert any(item["ip"] == ip for item in list_blocks())
    assert unblock_ip(ip)
    assert not is_blocked(ip)
