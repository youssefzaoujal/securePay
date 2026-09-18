"""Compliance as Code (Phase 3) — évaluation de l'inventaire PCI-DSS v4.0.1.

Le principe : chaque contrôle déclare des **preuves** (chemins du repo).
assess.py vérifie qu'elles existent, puis produit un rapport au format
OSCAL-lite. Ce n'est PAS une certification — c'est un scanner d'hygiène.

Usage:
    python -m compliance.assess            # rapport console
    python -m compliance.assess --json     # rapport JSON
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_controls(path: Path | None = None) -> dict[str, Any]:
    path = path or Path(__file__).parent / "controls.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    out = {}
    for item in doc.get("controls", []):
        cid = item["id"]
        out[cid] = {
            "requirement": item["requirement"],
            "category": item["category"],
            "status": item["status"],
            "evidence": [str(p) for p in item.get("evidence", [])],
        }
    return out


def _resolve(path: Path) -> bool:
    return path.is_dir() or path.is_file() or (ROOT / path).is_dir() or (ROOT / path).is_file()


def assess_control(control: dict[str, Any]) -> dict[str, Any]:
    missing = [ev for ev in control["evidence"] if not _resolve(Path(ev))]
    if missing:
        return {"status": "FAIL", "missing": missing}
    return {"status": "PASS", "missing": []}


def assess(report_json: bool = False) -> dict[str, Any]:
    controls = load_controls()
    items = {}
    pass_count = fail_count = 0
    for cid, control in controls.items():
        result = assess_control(control)
        items[cid] = {"requirement": control["requirement"], "category": control["category"], **result}
        if result["status"] == "PASS":
            pass_count += 1
        else:
            fail_count += 1
    total = len(controls)
    report = {
        "schema": "oscal-lite/assessment",
        "subject": "securepay-lab",
        "framework": "PCI-DSS v4.0.1",
        "summary": {
            "total": total,
            "pass": pass_count,
            "fail": fail_count,
            "coverage": f"{pass_count / total:.0%}" if total else "0",
        },
        "controls": items,
        "disclaimer": "scanner d'hygiène lab — ne constitue pas une certification (QSA).",
    }
    if report_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"[{report['framework']}] {pass_count}/{total} PASS, {fail_count} FAIL")
        for cid, item in items.items():
            status = item["status"]
            print(f"  {cid:<12} {status:<8} {item['requirement']}")
            for missing in item["missing"]:
                print(f"               preuve manquante : {missing}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    sys.exit(0 if assess(report_json=args.json)["summary"]["fail"] == 0 else 1)