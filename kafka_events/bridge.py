"""Pont Kafka thread-safe pour `shared.events.emit_event`.

`socket_emit_event` reste synchrone (appelé partout). Ce pont ouvre un
event-loop dédié sur un thread daemon et y pousse chaque événement sans
jamais bloquer le chemin de paiement. Sans broker configuré (env vide),
il ne fait rien — le JSONL continue de servir.

Usage:
    bridge = KafkaBridge.get()
    bridge.emit(payload)   # fire-and-forget
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from config import get_settings
from kafka_events.producer import KafkaEventBus

logger = logging.getLogger(__name__)


class KafkaBridge:
    """Singleton : loop + bus Kafka sur un thread daemon, safe depuis du sync."""

    _instance: "KafkaBridge | None" = None

    def __init__(self):
        self._bus: KafkaEventBus | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._started = False
        self._skip_reason = ""

    @classmethod
    def get(cls) -> "KafkaBridge":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def start(self) -> None:
        settings = get_settings()
        if self._started:
            return
        self._started = True
        if not settings.KAFKA_BOOTSTRAP_SERVERS:
            self._skip_reason = "KAFKA_BOOTSTRAP_SERVERS vide"
            return
        try:
            self._loop = asyncio.new_event_loop()
        except Exception as exc:  # pragma: no cover
            self._skip_reason = f"pas de loop dispo: {exc}"
            return
        self._thread = threading.Thread(target=self._run_loop, name="kafka-bridge", daemon=True)
        self._thread.start()
        logger.info("Pont Kafka démarré (broker=%s)", settings.KAFKA_BOOTSTRAP_SERVERS)

    def _run_loop(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        self._bus = KafkaEventBus(get_settings().KAFKA_BOOTSTRAP_SERVERS)
        self._loop.run_until_complete(self._bus.start())
        self._loop.run_forever()

    def emit(self, payload: dict[str, Any]) -> None:
        """Pousse l'événement vers Kafka — jamais bloquant pour l'appelant."""
        if not self._started:
            return
        if self._bus is None or self._loop is None or not self._bus.enabled:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._bus.send(payload), self._loop)
        except Exception:  # noqa: BLE001 — un broker down ne doit pas casser le 200
            logger.warning("Kafka bridge : envoi impossible, JSONL fait foi")


BRIDGE = KafkaBridge.get()