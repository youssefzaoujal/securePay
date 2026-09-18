"""Bus d'événements unifié : JSONL SOC + RabbitMQ optionnel.

Chaque décision de paiement, auth, fraude ou BOLA alimente le lab Detection.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.redaction import redact_secrets

_DEFAULT_LOG = Path(os.getenv("SECUREPAY_EVENT_LOG", "logs/securepay-events.jsonl"))


def _log_path() -> Path:
    path = Path(os.getenv("SECUREPAY_EVENT_LOG", str(_DEFAULT_LOG)))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def emit_event(event: dict[str, Any]) -> None:
    """Écrit un événement JSON structuré (PCI-DSS Req 10) vers le SOC.

    Toujours archivé en JSONL ; si `KAFKA_BOOTSTRAP_SERVERS` est configuré,
    le même événement part aussi vers Kafka (pont non bloquant, thread-safe).
    """
    payload = redact_secrets(dict(event))
    payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    payload.setdefault("source", "securepay")
    payload.setdefault("environment", os.getenv("APP_ENV", "lab"))
    line = json.dumps(payload, default=str)
    path = _log_path()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    try:
        from kafka_events.bridge import BRIDGE

        BRIDGE.start()
        BRIDGE.emit(payload)
    except Exception:  # noqa: BLE001 — l'archive JSONL reste la source de vérité
        pass
