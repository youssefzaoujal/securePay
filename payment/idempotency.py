"""Clés d'idempotence type Stripe (en-tête Idempotency-Key) — une capture = un effet métier."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class IdempotencyConflict(Exception):
    """Même clé, payload différent — ne pas recapturer."""


class IdempotencyStore:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    @staticmethod
    def fingerprint(payload: dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()

    def lookup(self, merchant_id: str, key: str) -> dict[str, Any] | None:
        return self._items.get(f"{merchant_id}:{key}")

    def remember(
        self,
        merchant_id: str,
        key: str,
        payload: dict[str, Any],
        payment_id: str,
    ) -> None:
        self._items[f"{merchant_id}:{key}"] = {
            "fingerprint": self.fingerprint(payload),
            "payment_id": payment_id,
        }

    def replay_or_conflict(
        self,
        merchant_id: str,
        key: str,
        payload: dict[str, Any],
    ) -> str | None:
        """Retourne payment_id si replay ; lève si conflit ; None si première fois."""
        existing = self.lookup(merchant_id, key)
        if not existing:
            return None
        if existing["fingerprint"] != self.fingerprint(payload):
            raise IdempotencyConflict("Idempotency-Key déjà utilisée avec un autre payload")
        return str(existing["payment_id"])


STORE = IdempotencyStore()
