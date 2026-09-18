"""ARGAUS-lite — supervision parc DAB (online / offline / maintenance)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

FLEET: dict[str, dict[str, Any]] = {
    "DAB_PARIS_01": {
        "id": "DAB_PARIS_01",
        "vendor": "ncr",
        "city": "Paris",
        "status": "ONLINE",
        "terminal_id": "NCRPARIS01",
    },
    "DAB_LYON_02": {
        "id": "DAB_LYON_02",
        "vendor": "diebold",
        "city": "Lyon",
        "status": "ONLINE",
        "terminal_id": "DBDLYON002",
    },
    "DAB_LILLE_03": {
        "id": "DAB_LILLE_03",
        "vendor": "wnx",
        "city": "Lille",
        "status": "MAINTENANCE",
        "terminal_id": "WNXLILLE03",
    },
    "DAB_MARSEILLE_04": {
        "id": "DAB_MARSEILLE_04",
        "vendor": "dn",
        "city": "Marseille",
        "status": "ONLINE",
        "terminal_id": "DNXMARS004",
    },
}


def list_atms() -> list[dict[str, Any]]:
    return list(FLEET.values())


def set_status(atm_id: str, status: str, reason: str = "") -> dict[str, Any]:
    if atm_id not in FLEET:
        raise KeyError(atm_id)
    FLEET[atm_id]["status"] = status
    FLEET[atm_id]["reason"] = reason
    FLEET[atm_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
    return FLEET[atm_id]


def heartbeat(atm_id: str) -> None:
    if atm_id in FLEET and FLEET[atm_id]["status"] != "MAINTENANCE":
        FLEET[atm_id]["status"] = "ONLINE"
        FLEET[atm_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
