"""Autorisation DAB — ISO 0200 → décision 0210 via fraude + core COBOL."""

from __future__ import annotations

import uuid
from typing import Any

from atm import argaus, journals
from atm.iso8583 import RC, build_0200, build_0210
from atm.profiles_loader import load_profile
from fraud.engine import FraudEngine
from payment.ledger import LEDGER
from shared.events import emit_event
from shared.redaction import mask_pan

FRAUD = FraudEngine()
WATCHLIST_PANS = {"4000000000000002"}  # LSB — liste de surveillance lab
TEST_PAN = "4111111111111111"


async def authorize(
    *,
    vendor: str,
    scenario: str,
    amount: float,
    pan: str = TEST_PAN,
    atm_id: str = "DAB_PARIS_01",
    merchant_id: str = "merchant-api",
) -> dict[str, Any]:
    profile = load_profile(vendor)
    terminal_id = profile["terminal_id_prefix"] + atm_id[-4:]
    stan = uuid.uuid4().hex[:6].upper()
    request = build_0200(
        scenario=scenario,
        pan=pan,
        amount=amount,
        terminal_id=terminal_id,
        merchant_id=merchant_id,
        stan=stan,
    )
    journals.write_mxa(
        {
            "atm_id": atm_id,
            "vendor": vendor,
            "device": profile.get("mxa_device_code"),
            "event": "iso8583_0200",
            "stan": stan,
            "scenario": scenario,
        }
    )
    argaus.heartbeat(atm_id)

    rc, reason = await _decide(scenario, pan, amount, merchant_id)
    rrn = uuid.uuid4().hex[:12].upper()
    response = build_0210(request, rc, rrn)

    journals.write_vte(
        {
            "atm_id": atm_id,
            "vendor": vendor,
            "stan": stan,
            "rrn": rrn,
            "scenario": scenario,
            "amount": amount,
            "response_code": rc,
            "pan_masked": mask_pan(pan),
            "valuation": "pending" if scenario == "deposit_unvalued" and rc == RC["approved"] else "posted",
        }
    )
    emit_event(
        {
            "event_type": "atm_authorization",
            "status": "succeeded" if rc == RC["approved"] else "failed",
            "scenario": scenario,
            "vendor": vendor,
            "atm_id": atm_id,
            "amount": amount,
            "response_code": rc,
            "source_ip": "10.8.0.10",
            "merchant_id": merchant_id,
        }
    )
    if rc == RC["approved"] and scenario in {"withdrawal", "deposit_valued"}:
        LEDGER.post_capture(f"atm_{rrn}", merchant_id, amount, "EUR")
    if scenario == "deposit_unvalued":
        journals.write_mxa(
            {
                "atm_id": atm_id,
                "event": "cassette_unvalued",
                "detail": "Dépôt non valorisé — encours en attente de reconnaissance",
            }
        )
    return {
        "request": request,
        "response": response,
        "response_code": rc,
        "reason": reason,
        "vendor": vendor,
        "profile": profile["family"],
        "atm_id": atm_id,
        "approved": rc == RC["approved"],
    }


async def _decide(scenario: str, pan: str, amount: float, merchant_id: str) -> tuple[str, str]:
    if pan in WATCHLIST_PANS or scenario == "lsb":
        return RC["restricted"], "LSB — carte en liste de surveillance"
    from payment.legacy_client import call_legacy_core

    core = await call_legacy_core(merchant_id, amount)
    if core == "DECLINED" or amount > 500_000:
        return RC["insufficient"], "core COBOL DECLINED ou plafond lab"
    fraud = FRAUD.analyze(amount, "EUR", "tok_atm", merchant_id, "10.8.0.10")
    if fraud.get("recommendation") == "decline":
        return RC["declined"], "fraude"
    if scenario == "deposit_unvalued":
        return RC["approved"], "dépôt accepté non valorisé (avis VTE pending)"
    return RC["approved"], "autorisation 0210"
