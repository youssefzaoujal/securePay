"""KaNest-lite — exécute les recettes YAML et alimente ALM + PV."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from atm.alm import add_defect, write_pv
from atm.engine import authorize

SCENARIOS = Path(__file__).resolve().parent / "scenarios.yaml"


def load_scenarios() -> list[dict[str, Any]]:
    return yaml.safe_load(SCENARIOS.read_text(encoding="utf-8")) or []


async def run_recipe(item: dict[str, Any]) -> dict[str, Any]:
    result = await authorize(
        vendor=item["vendor"],
        scenario=item["scenario"],
        amount=float(item["amount"]),
        pan=str(item.get("pan") or "4111111111111111"),
        atm_id=item.get("atm_id") or "DAB_PARIS_01",
    )
    expected = str(item["expected_rc"])
    actual = result["response_code"]
    passed = actual == expected
    row = {
        "id": item["id"],
        "title": item["title"],
        "vendor": item["vendor"],
        "scenario": item["scenario"],
        "expected_rc": expected,
        "actual_rc": actual,
        "status": "PASS" if passed else "FAIL",
        "reason": result.get("reason"),
        "stan": (result.get("request") or {}).get("named", {}).get("stan"),
    }
    if not passed:
        add_defect(
            title=f"[{item['id']}] {item['title']}",
            priority="high",
            context=row,
        )
    return row


async def run_all() -> dict[str, Any]:
    rows = [await run_recipe(item) for item in load_scenarios()]
    pv = write_pv(rows)
    return {
        "executed": len(rows),
        "passed": sum(1 for r in rows if r["status"] == "PASS"),
        "failed": sum(1 for r in rows if r["status"] == "FAIL"),
        "results": rows,
        "pv_path": str(pv),
    }
