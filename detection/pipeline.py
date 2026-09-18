"""Post-alerte : SOAR + ticket TheHive + enrichissement STIX + layer ATT&CK."""

from __future__ import annotations

from typing import Any

from detection.hive.case_manager import open_case
from detection.intel.enricher import enrich
from detection.sigma.mappings.generate_navigator import generate_from_alerts
from detection.soar.responder import auto_respond


def handle_alerts(alerts: list[Any]) -> dict[str, Any]:
    soar: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    intel: list[dict[str, Any]] = []
    for alert in alerts:
        result = auto_respond(alert)
        if result:
            soar.append(result)
        cases.append(open_case(alert))
        intel.append(enrich(alert))
    layer = generate_from_alerts(alerts)
    return {
        "soar": soar,
        "hive_cases": cases[-20:],
        "intel": intel[-20:],
        "navigator_techniques": len(layer.get("techniques") or []),
    }
