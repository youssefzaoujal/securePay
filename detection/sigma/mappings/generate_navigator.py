"""Régénère la layer ATT&CK Navigator après un run d'attaques."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_OUT = Path(__file__).resolve().parent / "attack_navigator_layer.auto.json"


def _out() -> Path:
    return Path(os.getenv("SECUREPAY_NAVIGATOR_OUT", str(DEFAULT_OUT)))


def generate_from_alerts(alerts: list[Any]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    for alert in alerts:
        data = alert if isinstance(alert, dict) else getattr(alert, "__dict__", {})
        for tid in data.get("mitre") or []:
            tid_s = str(tid).upper()
            if tid_s.startswith("T"):
                counts[tid_s] += 1
    techniques = [
        {
            "techniqueID": tid,
            "score": min(100, 40 + n * 15),
            "comment": f"fired {n} time(s) this run",
        }
        for tid, n in sorted(counts.items())
    ]
    if not techniques:
        techniques = [{"techniqueID": "T1657", "score": 0, "comment": "no alerts yet"}]
    layer = {
        "name": "SecurePay ATT&CK coverage (auto)",
        "versions": {"attack": "15", "navigator": "4.9"},
        "domain": "enterprise-attack",
        "description": "Généré automatiquement après evaluate() / attack lab.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#1565c0"],
            "minValue": 0,
            "maxValue": 100,
        },
    }
    path = _out()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    return layer
