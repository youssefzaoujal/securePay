"""Bus d'événements asynchrone (Kafka) — Phase 2.

Remplace / complète RabbitMQ pour le flux de paiement & fraude.
  - `KafkaEventBus` : producteur+consommateur aiokafka (config optionnelle).
  - Si `KAFKA_BOOTSTRAP_SERVERS` est vide (lab local sans broker), le producteur
    est dégradé en mode "JSONL" — le lab continue de fonctionner sans broker.
  - `emit_event` (même signature que `shared.events.emit_event`) bascule vers Kafka
    quand il est disponible, sinon JSONL.

Architecture : le bus d'événements est le même canal que le SOC — pas de silo.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable, Optional

from config import get_settings
from shared.redaction import redact_secrets

logger = logging.getLogger("securepay.kafka")

settings = get_settings()


def _producer_class():
    try:
        from aiokafka import AIOKafkaProducer
        return AIOKafkaProducer
    except Exception:  # pragma: no cover
        return None


class KafkaEventBus:
    """Producteur d'événements vers un topic ; repli JSONL si broker absent."""

    def __init__(self, bootstrap_servers: str | None = None, topic: str | None = None):
        self.bootstrap_servers = bootstrap_servers
        if not self.bootstrap_servers:
            self.bootstrap_servers = settings.KAFKA_BOOTSTRAP_SERVERS
        self.topic = topic or settings.KAFKA_EVENTS_TOPIC
        self._producer: Any = None
        producer_cls = _producer_class()
        self._producer_cls = producer_cls
        if self.bootstrap_servers and producer_cls:
            self._enabled = True
            logger.info("Kafka producer configuré sur %s (topic=%s)", self.bootstrap_servers, self.topic)
        else:
            self._enabled = False
            logger.info("Aucun broker Kafka — événements en repli JSONL")

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def start(self) -> None:
        if self._enabled and self._producer is None:
            self._producer = self._producer_cls(
                bootstrap_servers=self.bootstrap_servers,
                security_protocol=settings.KAFKA_SECURITY_PROTOCOL,
            )
            await self._producer.start()

    async def stop(self) -> None:
        if self._producer:
            try:
                await self._producer.stop()
            except Exception:  # pragma: no cover
                pass

    def serialize(self, event: dict[str, Any]) -> bytes:
        payload = redact_secrets(dict(event))
        return json.dumps(payload, default=str).encode("utf-8")

    async def send(self, event: dict[str, Any]) -> bool:
        """Publie un événement sur le topic. Retourne False si broker absent."""
        if not self._enabled or not self._producer:
            return False
        try:
            await self._producer.send(self.topic, value=self.serialize(event))
            await self._producer.flush()
            return True
        except Exception:  # noqa: BLE001 — le lab ne doit pas casser sur un broker down
            logger.warning("Envoi Kafka impossible, repli JSONL")
            return False


async def consume_events(handler: Callable[[dict[str, Any]], None], topic: str | None = None) -> None:
    """Boucle consommateur (à lancer dans une tâche). Bloque si broker présent."""
    if not settings.KAFKA_BOOTSTRAP_SERVERS:
        return
    from aiokafka import AIOKafkaConsumer

    consumer = AIOKafkaConsumer(
        topic or settings.KAFKA_EVENTS_TOPIC,
        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
        security_protocol=settings.KAFKA_SECURITY_PROTOCOL,
        value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
        auto_offset_reset="latest",
        group_id="securepay-soc",
    )
    await consumer.start()
    try:
        async for msg in consumer:
            handler(msg.value)
    finally:
        await consumer.stop()


# Singletons -------------------------------------------------------------------

_bus: Optional[KafkaEventBus] = None


def get_bus() -> KafkaEventBus:
    global _bus
    if _bus is None:
        _bus = KafkaEventBus()
    return _bus


def emit_event(event: dict[str, Any]) -> None:
    """Point d'entrée compatible avec `shared.events.emit_event`.

    Publie sur Kafka si un broker est configuré ; sinon délègue au JSONL.
    Le JSONL reste la source de vérité SOC — Kafka est un canal supplémentaire.
    """
    from shared.events import emit_event as _jsonl_emit

    bus = KafkaEventBus(settings.KAFKA_BOOTSTRAP_SERVERS)
    if bus.enabled:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(bus.start())
            sent = loop.run_until_complete(bus.send(event))
            loop.run_until_complete(bus.stop())
            if sent:
                return
        except Exception:  # noqa: BLE001
            pass
        finally:
            loop.close()
    _jsonl_emit(event)