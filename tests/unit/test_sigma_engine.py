"""Moteur Sigma — carding déclenche une alerte MITRE T1657."""

from detection.engine.sigma_engine import SigmaEngine


def test_card_testing_rule_fires_after_threshold():
    engine = SigmaEngine("detection/sigma/rules")
    assert engine.rules, "règles Sigma absentes"
    for _ in range(10):
        engine.evaluate_event(
            {
                "event_type": "payment_attempt",
                "status": "failed",
                "source_ip": "203.0.113.10",
                "merchant_id": "merchant-api",
                "amount": 1.0,
            }
        )
    titles = [alert.title for alert in engine.alerts]
    assert any("Card Testing" in title or "Card-Testing" in title for title in titles)
    assert any("T1657" in alert.mitre for alert in engine.alerts)


def test_bola_rule_requires_multiple_denies():
    engine = SigmaEngine("detection/sigma/rules")
    for _ in range(3):
        engine.evaluate_event(
            {
                "event_type": "authorization_error",
                "error_type": "object_level_authorization",
                "source_ip": "203.0.113.20",
                "merchant_id": "merchant-api",
                "target_merchant_id": "MERCH_999",
                "status_code": 403,
            }
        )
    assert any("BOLA" in alert.title for alert in engine.alerts)
