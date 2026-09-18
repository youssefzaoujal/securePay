"""Enrichissement type OpenCTI : bundle STIX 2.1 local (importable dans OpenCTI)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

BUNDLE_PATH = Path(__file__).resolve().parent / "stix_bundle.json"


def load_bundle() -> dict[str, Any]:
    if not BUNDLE_PATH.exists():
        return {"objects": []}
    return json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))


def enrich(alert: Any) -> dict[str, Any]:
    data = alert if isinstance(alert, dict) else getattr(alert, "__dict__", {})
    ip = data.get("source_ip")
    mitre = data.get("mitre") or []
    bundle = load_bundle()
    matches = []
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator" and ip and ip in json.dumps(obj):
            matches.append(obj.get("name") or obj.get("id"))
        if obj.get("type") == "attack-pattern":
            ext = (obj.get("external_references") or [{}])[0]
            if ext.get("external_id") in mitre:
                matches.append(obj.get("name"))
    return {
        "source_ip": ip,
        "mitre": mitre,
        "opencti_matches": matches,
        "bundle": str(BUNDLE_PATH),
    }
