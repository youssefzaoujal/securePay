"""Serveur/services gRPC internes — Phase 2.

Implémente `securepay.internal.v1` avec un serveur *à la main* sur grpc, sans
génération de code, afin de rester portable (pas de dépendance build-time). Les
_kernel_ délèguent aux moteurs existants du lab (fraud.engine, payment.routes)
pour prouver que le backbone gRPC est branché sur la vraie logique.

Le client (`grpc_svc.client`) utilise les stubs générés quand disponibles, et
replie sinon sur ça. Voir tests/unit/test_grpc_svc.py.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent import futures
from typing import Callable, Optional

import grpc

logger = logging.getLogger("securepay.grpc")

# Handlers métier injectables (raccordés aux moteurs du lab).
CreditHandler = Callable[[dict], dict]       # {payment_id, amount, card_token, ...} -> {status, reason_code}
RiskHandler = Callable[[dict], dict]         # {...} -> {risk_score, recommendation, challenge_required, flags}


async def _default_risk(request: dict) -> dict:
    """Raccord par défaut au moteur de fraude du lab (sync, exécuté dans un thread)."""
    from fraud.engine import FraudEngine

    engine = FraudEngine()
    res = await asyncio.to_thread(
        engine.analyze,
        request.get("amount", 0.0),
        request.get("currency", "EUR"),
        request.get("card_token", ""),
        request.get("merchant_id", ""),
        request.get("ip_address", ""),
    )
    return res


class _PaymentServicer:
    """Surrogate du stub publican ; le handler HTTP gRPC y route directement."""

    def __init__(self, capture: Optional[CreditHandler] = None):
        self._capture = capture or _default_capture

    async def process_capture(self, request: dict) -> dict:
        return await self._capture(request)


class _FraudServicer:
    def __init__(self, risk: Optional[RiskHandler] = None):
        self._risk = risk or _default_risk

    async def evaluate_risk(self, request: dict) -> dict:
        return await self._risk(request)


async def _default_capture(request: dict) -> dict:
    """Capture par défaut : enregistre la capture côté payment (mémoire du lab)."""
    from payment.routes import _PAYMENTS
    from payment.ledger import LEDGER

    payment_id = request.get("payment_id", "")
    status = "approved"
    reason_code = "00"
    if request.get("amount", 0) <= 0:
        status, reason_code = "declined", "51"
    else:
        amount = request.get("amount", 0.0)
        currency = request.get("currency", "EUR")
        merchant = request.get("merchant_id", "merchant")
        entries = LEDGER.post_capture(payment_id, merchant, amount, currency)
        rec = _PAYMENTS.setdefault(payment_id, {})
        rec.update(
            {
                "status": "succeeded",
                "amount": amount,
                "currency": currency,
                "three_ds_eci": request.get("three_ds_eci"),
                "three_ds_cavv": request.get("three_ds_cavv"),
                "ledger_entries": len(entries),
            }
        )
    return {"payment_id": payment_id, "status": status, "reason_code": reason_code}


# Wrap grpc : un seul service unary (service="securepay.internal.v1") + méthodes
# transportées par nom, pour éviter la génération de stubs. En prod on utiliserait
# les stubs grpcio compilés ; ici on documente l'équivalence.


class InternalService:
    """Implémentation gRPC unary, method name = `package.Method`."""

    def __init__(self, capture=None, risk=None):
        self._pay = _PaymentServicer(capture)
        self._risk_servicer = _FraudServicer(risk)

    async def dispatch(self, method: str, request: dict) -> dict:
        if method.endswith("ProcessCapture"):
            return await self._pay.process_capture(request)
        if method.endswith("EvaluateRisk"):
            return await self._risk_servicer.evaluate_risk(request)
        raise ValueError(f"Méthode gRPC inconnue: {method}")


class InProcessChannel:
    """Canal "in-process" sans socket : sert à tester/démontrer sans broker gRPC."""

    def __init__(self, service: InternalService):
        self._service = service

    async def invoke(self, method: str, request: dict) -> dict:
        return await self._service.dispatch(method, request)


def run_server(port: int = 50051, capture=None, risk=None, loop=None):
    """Démarre un vrai serveur gRPC (threads) sur InternalService.

    Comme on ne génère pas de stubs, on expose un service unary générique
    `securepay.internal.v1.Unary` dont le champ `method` + `request_json`
    transportent l'appel — équivalent démontrable du backbone gRPC sans
    build-time. Voir proto commentaire + docs/banking-stack.md.
    """
    from grpc_svc.raw_proto import serve_raw

    service = InternalService(capture=capture, risk=risk)
    serve_raw(port, service)
    return service


__all__ = ["InternalService", "InProcessChannel", "run_server", "_default_capture", "_default_risk"]