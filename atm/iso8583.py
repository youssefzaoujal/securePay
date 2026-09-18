"""ISO 8583 lab — sous-ensemble MTI 0200/0210 (autorisation DAB). Pas un switch ISO certifié."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Bitmap bits 1-based → noms de champs (lab)
FIELD_NAMES = {
    2: "pan",
    3: "processing_code",
    4: "amount",
    7: "transmission_datetime",
    11: "stan",
    37: "rrn",
    39: "response_code",
    41: "terminal_id",
    42: "merchant_id",
    49: "currency",
}

PROC = {
    "withdrawal": "010000",
    "deposit_valued": "210000",
    "deposit_unvalued": "220000",
    "lsb": "960000",
}

RC = {
    "approved": "00",
    "declined": "05",
    "insufficient": "51",
    "restricted": "62",  # LSB / liste de surveillance
    "error": "96",
}


def _amount_iso(amount: float) -> str:
    cents = int(round(float(amount) * 100))
    return f"{cents:012d}"


def from_iso_amount(raw: str) -> float:
    return int(raw or "0") / 100.0


def build_0200(
    *,
    scenario: str,
    pan: str,
    amount: float,
    terminal_id: str,
    merchant_id: str,
    currency: str = "978",
    stan: str = "000001",
) -> dict[str, Any]:
    proc = PROC[scenario]
    now = datetime.now(timezone.utc).strftime("%m%d%H%M%S")
    fields = {
        2: pan,
        3: proc,
        4: _amount_iso(amount),
        7: now,
        11: stan.zfill(6)[:6],
        41: terminal_id[:16],
        42: merchant_id[:15],
        49: currency,
    }
    bits = 0
    for num in fields:
        bits |= 1 << (64 - num)
    bitmap = f"{bits:016X}"
    named = {FIELD_NAMES[k]: v for k, v in fields.items()}
    return {
        "mti": "0200",
        "bitmap": bitmap,
        "fields": fields,
        "named": named,
        "scenario": scenario,
        "wire": f"0200{bitmap}|{named}",
    }


def build_0210(request: dict[str, Any], response_code: str, rrn: str) -> dict[str, Any]:
    fields = dict(request.get("fields") or {})
    fields[37] = rrn[:12]
    fields[39] = response_code
    named = {FIELD_NAMES[k]: v for k, v in fields.items() if k in FIELD_NAMES}
    bits = 0
    for num in fields:
        bits |= 1 << (64 - num)
    return {
        "mti": "0210",
        "bitmap": f"{bits:016X}",
        "fields": fields,
        "named": named,
        "response_code": response_code,
        "wire": f"0210{bits:016X}|{named}",
    }


def scenario_from_proc(code: str) -> str:
    for name, value in PROC.items():
        if value == code:
            return name
    return "withdrawal"
