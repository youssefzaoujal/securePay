"""Tests unitaires des règles Sigma (vrai positif / faux positif) + mapping MITRE."""

from detection.engine.sigma_engine import SigmaEngine


def _engine() -> SigmaEngine:
    return SigmaEngine("detection/sigma/rules")


def test_carding_fires_at_threshold_not_before():
    engine = _engine()
    ip = "203.0.113.40"
    event = {"event_type": "payment_attempt", "status": "failed", "source_ip": ip, "merchant_id": "m"}
    for _ in range(9):
        engine.evaluate_event(event)
    assert engine.alerts == []
    engine.evaluate_event(event)
    assert any("T1657" in a.mitre for a in engine.alerts)


def test_carding_ignores_successes():
    engine = _engine()
    for _ in range(12):
        engine.evaluate_event(
            {"event_type": "payment_attempt", "status": "succeeded", "source_ip": "203.0.113.41"}
        )
    assert not any("Card Testing" in a.title for a in engine.alerts)


def test_bola_threshold_and_mitre():
    engine = _engine()
    ev = {
        "event_type": "authorization_error",
        "error_type": "object_level_authorization",
        "source_ip": "198.51.100.8",
        "status_code": 403,
    }
    engine.evaluate_event(ev)
    engine.evaluate_event(ev)
    assert engine.alerts == []
    engine.evaluate_event(ev)
    assert any("T1213" in a.mitre for a in engine.alerts)


def test_jwt_replay_fires_once():
    engine = _engine()
    fired = engine.evaluate_event({"event_type": "jwt_replay", "status": "blocked", "jti": "abc"})
    assert fired and "T1550.001" in fired[0].mitre


def test_sql_injection_and_pan_leak_and_stuffing():
    engine = _engine()
    assert engine.evaluate_event({"event_type": "injection_probe", "status": "blocked"})
    assert engine.evaluate_event({"event_type": "pan_leakage"})
    stuffing = {"event_type": "authentication_attempt", "status": "failed", "source_ip": "192.0.2.9"}
    for _ in range(4):
        engine.evaluate_event(stuffing)
    assert not any("Stuffing" in a.title for a in engine.alerts)
    engine.evaluate_event(stuffing)
    assert any("T1110.004" in a.mitre or "T1110" in a.mitre for a in engine.alerts)


def test_fraud_anomaly_needs_cluster():
    engine = _engine()
    ev = {"event_type": "fraud_score", "risk_score": 0.91, "source_ip": "203.0.113.50"}
    for _ in range(4):
        engine.evaluate_event(ev)
    assert not any("Fraud Score" in a.title for a in engine.alerts)
    engine.evaluate_event(ev)
    assert any("T1657" in a.mitre for a in engine.alerts)
