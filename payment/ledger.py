"""Grand livre en partie double + réconciliation (lab, en mémoire)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

Side = Literal["debit", "credit"]


@dataclass(frozen=True)
class Entry:
    account: str
    side: Side
    amount: float
    currency: str
    payment_id: str
    at: str


@dataclass
class Ledger:
    entries: list[Entry] = field(default_factory=list)
    posted_payments: set[str] = field(default_factory=set)

    def post_capture(self, payment_id: str, merchant_id: str, amount: float, currency: str) -> list[Entry]:
        """Débit scheme_receivable / crédit merchant_payable — une seule fois par payment_id."""
        if payment_id in self.posted_payments:
            return [e for e in self.entries if e.payment_id == payment_id]
        if amount <= 0:
            raise ValueError("montant de capture invalide")
        now = datetime.now(timezone.utc).isoformat()
        pair = [
            Entry("assets:scheme_receivable", "debit", amount, currency, payment_id, now),
            Entry(f"liabilities:merchant:{merchant_id}", "credit", amount, currency, payment_id, now),
        ]
        self.entries.extend(pair)
        self.posted_payments.add(payment_id)
        return pair

    def balance(self, account: str | None = None) -> float:
        total = 0.0
        for entry in self.entries:
            if account and entry.account != account:
                continue
            total += entry.amount if entry.side == "debit" else -entry.amount
        return round(total, 2)

    def reconcile(self, currency: str = "EUR") -> dict:
        """Somme des débits = somme des crédits (partie double)."""
        debits = sum(e.amount for e in self.entries if e.side == "debit" and e.currency == currency)
        credits = sum(e.amount for e in self.entries if e.side == "credit" and e.currency == currency)
        balanced = round(debits - credits, 2) == 0.0

        result = {
            "currency": currency,
            "debits": round(debits, 2),
            "credits": round(credits, 2),
            "delta": round(debits - credits, 2),
            "balanced": balanced,
            "entries": len(self.entries),
            "captures": len(self.posted_payments),
        }
        # Écart financier → événement SOC (détection avec la même infra que la sécu).
        if not balanced:
            _emit_reconciliation_breakdown(result, currency)
        return result


def _emit_reconciliation_breakdown(result: dict, currency: str) -> None:
    """Un écart de réconciliation est traité comme une anomalie de détection.

    La règle Sigma `ledger_reconciliation_breakdown` lève une alerte critique :
    l'intégrité financière est surveillée par le même pipeline que la sécurité.
    """
    from shared.events import emit_event

    emit_event(
        {
            "event_type": "ledger_reconciliation",
            "scenario": "ledger_reconciliation_breakdown",
            "currency": currency,
            "debits": result["debits"],
            "credits": result["credits"],
            "delta": result["delta"],
            "status": "breakdown",
            "detection_signal": "ledger_unbalanced_double_entry",
            "entries": result["entries"],
            "captures": result["captures"],
        }
    )


LEDGER = Ledger()
