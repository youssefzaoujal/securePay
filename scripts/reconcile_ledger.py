#!/usr/bin/env python3
"""Réconciliation nocturne — compare le ledger en partie double à l'état du payment service.

Usage (cron nocturne / CI) :
    python -m scripts.reconcile_ledger

Sur animate un écart :
  - événement `ledger_reconciliation` → bus SOC (règle Sigma dédiée lève une alerte)
  - exit code 1 (bloquant pour la CI/le run glissant)

Idée de design : l'intégrité financière est surveillée avec la MÊME infra de
détection que la sécurité (Sigma + MITRE + SOAR) — rien de nouveau à opérer.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone

from payment.ledger import LEDGER
from payment import routes as payment_routes
from shared.events import emit_event


async def reconcile() -> dict:
    # 1) Partie double : débits = crédits.
    ledger_status = LEDGER.reconcile()

    # 2) Croisement avec l'état du service payment (captures enregistrées).
    payment_ids_in_ledger = set(LEDGER.posted_payments)
    payment_ids_in_service = {pid for pid, row in payment_routes._PAYMENTS.items() if row.get("status") == "succeeded"}
    missed_captures = payment_ids_in_service - payment_ids_in_ledger
    orphan_ledger = payment_ids_in_ledger - payment_ids_in_service

    drift = {
        "balanced": ledger_status["balanced"],
        "missing_captures": len(missed_captures),
        "missing_capture_list": sorted(missed_captures),
        "orphan_ledger_entries": len(orphan_ledger),
        "orphan_ledger_list": sorted(orphan_ledger),
        "captures_ok": len(payment_ids_in_service & payment_ids_in_ledger),
    }

    emit_event(
        {
            "event_type": "ledger_reconciliation",
            "scenario": "reconciliation_drift",
            "status": "ok" if (ledger_status["balanced"] and not missed_captures and not orphan_ledger) else "drift",
            "debits": ledger_status["debits"],
            "credits": ledger_status["credits"],
            "delta": ledger_status["delta"],
            "captures_ok": drift["captures_ok"],
            "missing_captures": len(missed_captures),
            "orphan_ledger_entries": len(orphan_ledger),
            "run_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    return {**ledger_status, **drift}


def main() -> int:
    result = asyncio.run(reconcile())
    print(
        f"[reconcile] balanced={result['balanced']} "
        f"debits={result['debits']} credits={result['credits']} delta={result['delta']} "
        f"missing={result['missing_captures']} orphan={result['orphan_ledger_entries']}"
    )
    if not result["balanced"] or result["missing_captures"] or result["orphan_ledger_entries"]:
        print("[reconcile] DÉSALIGNEMENT détecté — événement envoyé au SOC (Sigma: ledger_reconciliation_breakdown)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())