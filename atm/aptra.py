"""APTRA Vision-lite — reporting technique × financier par DAB."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from atm import argaus
from atm.journals import tail
from payment.ledger import LEDGER


def report() -> dict[str, Any]:
    by_atm: dict[str, dict[str, Any]] = defaultdict(lambda: {"tx": 0, "approved": 0, "amount": 0.0})
    for event in tail("vte", limit=200):
        atm_id = event.get("atm_id") or "unknown"
        by_atm[atm_id]["tx"] += 1
        if event.get("response_code") == "00":
            by_atm[atm_id]["approved"] += 1
            by_atm[atm_id]["amount"] += float(event.get("amount") or 0)
    fleet = {atm["id"]: atm for atm in argaus.list_atms()}
    rows = []
    for atm_id, stats in by_atm.items():
        meta = fleet.get(atm_id, {})
        rows.append(
            {
                "atm_id": atm_id,
                "vendor": meta.get("vendor"),
                "status": meta.get("status"),
                "city": meta.get("city"),
                **stats,
            }
        )
    if not rows:
        rows = [
            {
                "atm_id": atm["id"],
                "vendor": atm.get("vendor"),
                "status": atm.get("status"),
                "city": atm.get("city"),
                "tx": 0,
                "approved": 0,
                "amount": 0.0,
            }
            for atm in fleet.values()
        ]
    recon = LEDGER.reconcile()
    return {"atms": rows, "ledger": recon, "source": "aptra-vision-lite"}
