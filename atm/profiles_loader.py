"""Charge les profils constructeur (NCR, Diebold, WNX, DN)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"


def load_profile(vendor: str) -> dict[str, Any]:
    path = PROFILES_DIR / f"{vendor.lower()}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Profil constructeur inconnu: {vendor} (ncr|diebold|wnx|dn)")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def list_vendors() -> list[str]:
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))
