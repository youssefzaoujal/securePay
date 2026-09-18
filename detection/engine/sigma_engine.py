"""Moteur Sigma-lite : évalue les règles YAML contre le flux JSONL SecurePay."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    count: int
    source_ip: str | None
    merchant_id: str | None
    timestamp: str
    sample: dict[str, Any]
    recommended_actions: list[str] = field(default_factory=list)


def _parse_timeframe(raw: str | None) -> float:
    if not raw:
        return 300.0
    raw = str(raw).strip().lower()
    if raw.endswith("m"):
        return float(raw[:-1]) * 60
    if raw.endswith("s"):
        return float(raw[:-1])
    if raw.endswith("h"):
        return float(raw[:-1]) * 3600
    return float(raw)


def _cmp(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return actual in expected
    if isinstance(expected, str):
        for op in (">=", "<=", ">", "<"):
            if expected.startswith(op):
                try:
                    return {
                        ">=": float(actual) >= float(expected[len(op) :].strip()),
                        "<=": float(actual) <= float(expected[len(op) :].strip()),
                        ">": float(actual) > float(expected[len(op) :].strip()),
                        "<": float(actual) < float(expected[len(op) :].strip()),
                    }[op]
                except (TypeError, ValueError):
                    return False
    return actual == expected


def _matches(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    return all(_cmp(event.get(key), expected) for key, expected in selection.items())


class SigmaEngine:
    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        self.rules: list[dict[str, Any]] = []
        self._windows: dict[str, deque] = defaultdict(deque)
        self.alerts: list[Alert] = []
        self.load()

    def load(self) -> None:
        self.rules = []
        if not self.rules_dir.exists():
            return
        for path in sorted(self.rules_dir.glob("*.yml")):
            if yaml is None:
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            data["_file"] = path.name
            self.rules.append(data)

    def evaluate_event(self, event: dict[str, Any]) -> list[Alert]:
        fired: list[Alert] = []
        now = datetime.now(timezone.utc).timestamp()
        for rule in self.rules:
            detection = rule.get("detection") or {}
            selections = {
                name: spec
                for name, spec in detection.items()
                if name.startswith("selection") and isinstance(spec, dict)
            }
            if not selections:
                continue
            if not all(_matches(event, spec) for spec in selections.values()):
                continue

            timeframe = _parse_timeframe(detection.get("timeframe") or rule.get("timeframe"))
            threshold = int(detection.get("count") or 1)
            group = event.get("source_ip") or event.get("merchant_id") or "global"
            key = f"{rule.get('id', rule.get('title'))}:{group}"
            window = self._windows[key]
            window.append(now)
            while window and now - window[0] > timeframe:
                window.popleft()
            if len(window) < threshold:
                continue

            tags = rule.get("tags") or []
            mitre = [t.replace("attack.", "").upper() if isinstance(t, str) else str(t) for t in tags if "t1" in str(t).lower() or "t0" in str(t).lower()]
            extra = (rule.get("output") or {}).get("mitre_attack") or []
            for item in extra:
                tid = item.get("technique") if isinstance(item, dict) else None
                if tid:
                    mitre.append(tid)
            mitre = sorted(set(mitre))
            actions = (rule.get("output") or {}).get("recommended_actions") or []
            alert = Alert(
                rule_id=str(rule.get("id") or rule.get("_file")),
                title=rule.get("title", "SecurePay alert"),
                severity=str(rule.get("level") or "medium"),
                mitre=mitre,
                count=len(window),
                source_ip=event.get("source_ip"),
                merchant_id=event.get("merchant_id"),
                timestamp=event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                sample=event,
                recommended_actions=list(actions),
            )
            self.alerts.append(alert)
            fired.append(alert)
            window.clear()
        return fired

    def ingest_file(self, path: Path) -> list[Alert]:
        fired: list[Alert] = []
        if not path.exists():
            return fired
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fired.extend(self.evaluate_event(event))
        return fired
