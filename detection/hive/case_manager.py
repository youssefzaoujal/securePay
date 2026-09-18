"""TheHive-compatible case manager — fichier local + API si THEHIVE_URL est défini."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def _cases_file() -> Path:
    return Path(os.getenv("SECUREPAY_HIVE_CASES", "logs/thehive-cases.jsonl"))


def _alert_dict(alert: Any) -> dict[str, Any]:
    if isinstance(alert, dict):
        return alert
    return getattr(alert, "__dict__", {}) or {}


def open_case(alert: Any) -> dict[str, Any]:
    data = _alert_dict(alert)
    case = {
        "id": f"TH-{uuid.uuid4().hex[:8]}",
        "title": data.get("title") or "SecurePay alert",
        "severity": data.get("severity") or "medium",
        "tlp": 2,
        "pap": 2,
        "tags": ["securepay", "sigma", *(data.get("mitre") or [])],
        "source": "securepay-sigma",
        "sourceRef": data.get("rule_id"),
        "description": json.dumps(data.get("sample") or {}, default=str)[:2000],
        "source_ip": data.get("source_ip"),
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "status": "New",
        "observables": [
            {"dataType": "ip", "data": data.get("source_ip"), "tags": ["attacker"]}
        ]
        if data.get("source_ip")
        else [],
    }
    for existing in list_cases(limit=200):
        if (
            existing.get("sourceRef") == case["sourceRef"]
            and existing.get("source_ip") == case["source_ip"]
            and existing.get("title") == case["title"]
        ):
            return existing
    path = _cases_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(case) + "\n")
    _push_thehive(case)
    return case


def _push_thehive(case: dict[str, Any]) -> None:
    url = os.getenv("THEHIVE_URL", "").rstrip("/")
    key = os.getenv("THEHIVE_API_KEY", "")
    if not url or not key:
        return
    try:
        import httpx

        httpx.post(
            f"{url}/api/v1/alert",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "type": "securepay",
                "source": case["source"],
                "sourceRef": case["sourceRef"] or case["id"],
                "title": case["title"],
                "description": case["description"],
                "severity": 3 if str(case["severity"]).lower() == "critical" else 2,
                "tags": case["tags"],
            },
            timeout=5.0,
        )
    except Exception:
        return


def list_cases(limit: int = 20) -> list[dict[str, Any]]:
    path = _cases_file()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines[-limit:]]
