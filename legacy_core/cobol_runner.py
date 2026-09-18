"""Exécute le binaire GnuCOBOL (argv uniquement, jamais shell=True)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from legacy_core.sanitize import cents, validate_account_id, validate_amount

DEFAULT_BINARY = Path(__file__).resolve().parent / "bin" / "validate"
DEFAULT_BALANCE = 500_000.00


def binary_path() -> Path:
    override = os.getenv("LEGACY_COBOL_BIN")
    return Path(override) if override else DEFAULT_BINARY


def decide(account_id: str, amount: float) -> str:
    """APPROVED / DECLINED — même règle métier que VALIDATE.cob."""
    account = validate_account_id(account_id)
    safe_amount = validate_amount(amount)
    bin_path = binary_path()
    if bin_path.is_file() and os.access(bin_path, os.X_OK):
        return _run_cobol(bin_path, account, safe_amount)
    if os.getenv("LEGACY_CORE_ALLOW_FALLBACK", "").lower() in {"1", "true", "yes"}:
        return "APPROVED" if safe_amount <= DEFAULT_BALANCE else "DECLINED"
    raise FileNotFoundError(f"Binaire COBOL absent: {bin_path}")


def _run_cobol(bin_path: Path, account_id: str, amount: float) -> str:
    padded = account_id.ljust(10)
    result = subprocess.run(  # noqa: S603
        [str(bin_path), padded, cents(amount)],
        capture_output=True,
        text=True,
        timeout=2.0,
        check=False,
        shell=False,
    )
    status = (result.stdout or "").strip().splitlines()
    last = status[-1].strip().upper() if status else ""
    if last in {"APPROVED", "DECLINED"}:
        return last
    return "DECLINED"


def cobc_available() -> bool:
    return shutil.which("cobc") is not None
