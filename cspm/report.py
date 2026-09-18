"""Rapports JSON + HTML CIS."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_reports(findings: list[dict[str, Any]], out_dir: Path) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark": "CIS AWS Foundations Benchmark v3.0.0 (subset)",
        "finding_count": len(findings),
        "findings": findings,
    }
    json_path = out_dir / f"cspm-{stamp}.json"
    html_path = out_dir / f"cspm-{stamp}.html"
    latest_json = out_dir / "cspm-latest.json"
    latest_html = out_dir / "cspm-latest.html"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest_json.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
    html = _html(payload)
    html_path.write_text(html, encoding="utf-8")
    latest_html.write_text(html, encoding="utf-8")
    return {"json": str(latest_json), "html": str(latest_html)}


def _html(payload: dict[str, Any]) -> str:
    rows = []
    for item in payload["findings"]:
        rows.append(
            "<tr>"
            f"<td>{item.get('severity')}</td>"
            f"<td>{item.get('id')}</td>"
            f"<td>{item.get('title')}</td>"
            f"<td>{item.get('resource')}</td>"
            f"<td>{item.get('cis')}</td>"
            "</tr>"
        )
    body = "".join(rows) or "<tr><td colspan=5>Aucun finding</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"/><title>SecurePay CSPM</title>
<style>
body{{font-family:sans-serif;background:#0b0b14;color:#eee;margin:24px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #333;padding:8px;text-align:left}}
th{{background:#1a1a2e}}
.CRITICAL{{color:#ff4d6d}} .HIGH{{color:#ffb020}}
</style></head><body>
<h1>SecurePay CSPM — CIS AWS Foundations</h1>
<p>{payload['finding_count']} findings · {payload['generated_at']}</p>
<p>Simulation / posture lab. Ne remplace pas un audit CIS officiel.</p>
<table><thead><tr><th>Sévérité</th><th>ID</th><th>Titre</th><th>Ressource</th><th>Contrôle CIS</th></tr></thead>
<tbody>{body}</tbody></table>
</body></html>"""
