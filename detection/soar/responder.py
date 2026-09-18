"""Réponse automatique type SOAR : alerte Sigma critique → blocage IP (TTL 1h)."""

from __future__ import annotations

from detection.soar.blocklist import block_ip
from shared.events import emit_event

AUTO_SEVERITIES = {"critical", "high"}
AUTO_SIGNALS = {
    "card_testing",
    "carding",
    "bola",
    "jwt_replay",
    "credential_stuffing",
    "injection_probe",
    "sql_injection",
}


def _alert_dict(alert) -> dict:
    if isinstance(alert, dict):
        return alert
    return getattr(alert, "__dict__", {}) or {}


def should_auto_block(alert) -> bool:
    data = _alert_dict(alert)
    severity = str(data.get("severity") or data.get("level") or "").lower()
    title = str(data.get("title") or "").lower()
    sample = data.get("sample") or {}
    scenario = str(sample.get("scenario") or data.get("scenario") or "").lower()
    event_type = str(sample.get("event_type") or "").lower()
    if severity in AUTO_SEVERITIES:
        return True
    blob = f"{title} {scenario} {event_type}"
    return any(signal in blob for signal in AUTO_SIGNALS)


def auto_respond(alert) -> dict | None:
    data = _alert_dict(alert)
    if not should_auto_block(data):
        return None
    sample = data.get("sample") or {}
    ip = data.get("source_ip") or sample.get("source_ip")
    if not ip:
        return None
    reason = data.get("title") or "sigma-alert"
    result = block_ip(ip, reason=reason, ttl_seconds=3600, alert=data)
    emit_event(
        {
            "event_type": "soar_ip_block",
            "status": "blocked",
            "source_ip": ip,
            "reason": reason,
            "severity": data.get("severity"),
            "detection_signal": "automated_response",
        }
    )
    return result
