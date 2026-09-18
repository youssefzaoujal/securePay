"""HP ALM Lite — cycle NEW → IN_PROGRESS → FIXED → CLOSED + PV HTML."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUSES = ("NEW", "IN_PROGRESS", "FIXED", "CLOSED")


def _defects_file() -> Path:
    return Path(os.getenv("SECUREPAY_ALM_DEFECTS", "logs/alm-defects.jsonl"))


def add_defect(*, title: str, priority: str = "medium", context: dict[str, Any] | None = None) -> dict[str, Any]:
    ticket = {
        "id": f"ALM-{uuid.uuid4().hex[:8]}",
        "title": title,
        "priority": priority,
        "status": "NEW",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "context": context or {},
    }
    path = _defects_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(ticket, default=str) + "\n")
    return ticket


def list_defects(limit: int = 50) -> list[dict[str, Any]]:
    path = _defects_file()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines[-limit:]]


def transition(defect_id: str, status: str) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(status)
    items = list_defects(limit=500)
    found = None
    for item in items:
        if item.get("id") == defect_id:
            item["status"] = status
            item["updated_at"] = datetime.now(timezone.utc).isoformat()
            found = item
    if not found:
        raise KeyError(defect_id)
    path = _defects_file()
    path.write_text("".join(json.dumps(i, default=str) + "\n" for i in items), encoding="utf-8")
    return found


def write_pv(results: list[dict[str, Any]]) -> Path:
    passed = sum(1 for r in results if r.get("status") == "PASS")
    failed = len(results) - passed
    rows = "".join(
        f"<tr><td>{r.get('id')}</td><td>{r.get('title')}</td><td>{r.get('vendor')}</td>"
        f"<td>{r.get('expected_rc')}</td><td>{r.get('actual_rc')}</td><td>{r.get('status')}</td></tr>"
        for r in results
    )
    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"/><title>PV de recette DAB</title>
<style>body{{font-family:sans-serif;max-width:900px;margin:2rem auto}} td,th{{border:1px solid #ccc;padding:6px}}</style>
</head><body>
<h1>Procès-verbal de recette — canal DAB (lab)</h1>
<p>Simulation SecurePay. PAN de test uniquement. Outils PFA <em>simulés</em> (pas HP ALM / KaNest licence).</p>
<p>Exécuté : {datetime.now(timezone.utc).isoformat()} — PASS {passed} / FAIL {failed} / total {len(results)}</p>
<table><thead><tr><th>ID</th><th>Recette</th><th>Constructeur</th><th>RC attendu</th><th>RC obtenu</th><th>Statut</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
    out = Path(os.getenv("SECUREPAY_PV_DIR", "logs")) / "pv-recette-dab.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out
