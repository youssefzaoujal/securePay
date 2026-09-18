"""MXA (technique automate) vs VTE (avis financiers) — deux journaux distincts."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.redaction import redact_secrets


def _path(kind: str) -> Path:
    name = "mxa-technical.jsonl" if kind == "mxa" else "vte-financial.jsonl"
    return Path(os.getenv("SECUREPAY_ATM_LOG_DIR", "logs")) / name


def write_mxa(event: dict[str, Any]) -> None:
    _append("mxa", {"channel": "mxa", **event})


def write_vte(event: dict[str, Any]) -> None:
    _append("vte", {"channel": "vte", **event})


def _append(kind: str, event: dict[str, Any]) -> None:
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    path = _path(kind)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(redact_secrets(event), default=str) + "\n")


def tail(kind: str, limit: int = 30) -> list[dict[str, Any]]:
    path = _path(kind)
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines[-limit:]]
