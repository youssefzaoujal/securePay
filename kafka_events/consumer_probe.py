#!/usr/bin/env python3
"""Probe consommateur Kafka — vérifie le bus d'événements bout-en-bout.

    python -m kafka_events.consumer_probe --seconds 10

Publie un événement de contrôle sur `securepay.events` et attend de le relire.
Sortie 0 si round-trip OK, 1 sinon. Sans broker (KAFKA_BOOTSTRAP_SERVERS vide),
le probe ne fait rien et sort 0 (repli JSONL documenté).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from kafka_events.producer import KafkaEventBus


async def _probe(seconds: int) -> int:
    from config import get_settings
    from kafka_events.producer import settings

    if not settings.KAFKA_BOOTSTRAP_SERVERS:
        print("[kafka-probe] KAFKA_BOOTSTRAP_SERVERS vide -> repli JSONL (pas de broker a tester)")
        return 0

    from aiokafka import AIOKafkaConsumer

    topic = settings.KAFKA_EVENTS_TOPIC
    producer = KafkaEventBus()
    await producer.start()
    ok = False
    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
        auto_offset_reset="earliest",
        group_id="kafka-consumer-probe",
        value_deserializer=lambda raw: raw.decode(),
    )
    await consumer.start()
    try:
        import time as _t

        deadline = _t.time() + seconds
        probe = {"event_type": "probe", "source": "kafka_events.consumer_probe", "ts": _t.time()}
        await producer.send(probe)
        while _t.time() < deadline:
            try:
                msg = await asyncio.wait_for(consumer.getone(), timeout=2)
            except asyncio.TimeoutError:
                continue
            if "kafka_events.consumer_probe" in msg.value:
                ok = True
                break
    finally:
        await consumer.stop()
        await producer.stop()

    print("[kafka-probe]", "OK round-trip" if ok else "ECHEC round-trip")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args()
    return asyncio.run(_probe(args.seconds))


if __name__ == "__main__":
    sys.exit(main())