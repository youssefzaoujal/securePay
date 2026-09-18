"""SOC API — ingestion, évaluation Sigma, cartographie MITRE ATT&CK."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from detection.engine.sigma_engine import SigmaEngine
from detection.hive.case_manager import list_cases
from detection.pipeline import handle_alerts
from detection.soar.blocklist import list_blocks, unblock_ip
from shared.events import emit_event
from shared.http import mount_security
from shared.metrics import DETECTION_ALERTS, SIGMA_EVAL_SECONDS

RULES_DIR = Path("detection/sigma/rules")
MAPPING_PATH = Path("detection/sigma/mappings/mitre_attack.json")
EVENT_LOG = Path("logs/securepay-events.jsonl")
SIM_LOG_DIR = Path("detection/simulator/logs")

app = FastAPI(
    title="SecurePay SOC — Detection Engine",
    version="1.0.0",
    description="Sigma-as-code + MITRE ATT&CK overlay for the SecurePay payment lab.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
mount_security(app)

engine = SigmaEngine(RULES_DIR)


class IngestEvent(BaseModel):
    payload: dict = Field(default_factory=dict)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "detection-engine",
        "rules_loaded": len(engine.rules),
        "alerts": len(engine.alerts),
    }


@app.get("/rules")
async def list_rules():
    return [
        {
            "id": rule.get("id"),
            "title": rule.get("title"),
            "level": rule.get("level"),
            "file": rule.get("_file"),
            "tags": rule.get("tags"),
        }
        for rule in engine.rules
    ]


@app.get("/mitre")
async def mitre_mapping():
    if not MAPPING_PATH.exists():
        raise HTTPException(status_code=404, detail="Mapping MITRE absent")
    return json.loads(MAPPING_PATH.read_text(encoding="utf-8"))


def _count_alerts(fired) -> None:
    for alert in fired:
        DETECTION_ALERTS.labels(
            rule=alert.rule_id,
            severity=alert.severity,
            mitre=",".join(alert.mitre) or "none",
        ).inc()


@app.post("/ingest")
async def ingest(event: dict):
    fired = engine.evaluate_event(event)
    emit_event(event)
    _count_alerts(fired)
    pipeline = handle_alerts(fired)
    return {
        "ingested": True,
        "alerts": [alert.__dict__ for alert in fired],
        "soar": pipeline["soar"],
        "hive_cases": pipeline["hive_cases"],
        "intel": pipeline["intel"],
    }


@app.post("/evaluate")
async def evaluate_logs():
    engine.load()
    fired = []
    with SIGMA_EVAL_SECONDS.time():
        if EVENT_LOG.exists():
            fired.extend(engine.ingest_file(EVENT_LOG))
        if SIM_LOG_DIR.exists():
            for path in SIM_LOG_DIR.glob("*.jsonl"):
                fired.extend(engine.ingest_file(path))
    _count_alerts(fired)
    pipeline = handle_alerts(fired)
    return {
        "alerts_fired": len(fired),
        "alerts_total": len(engine.alerts),
        "alerts": [a.__dict__ for a in engine.alerts[-50:]],
        "soar_blocks": list_blocks(),
        "hive_cases": pipeline["hive_cases"],
        "intel": pipeline["intel"],
        "navigator_techniques": pipeline["navigator_techniques"],
    }


@app.get("/alerts")
async def alerts(limit: int = 50):
    return [a.__dict__ for a in engine.alerts[-limit:]]


@app.get("/hive/cases")
async def hive_cases(limit: int = 20):
    return list_cases(limit=limit)


@app.get("/intel")
async def threat_intel():
    from detection.intel.enricher import load_bundle

    return load_bundle()


@app.get("/mitre/navigator")
async def navigator_layer():
    auto = Path("detection/sigma/mappings/attack_navigator_layer.auto.json")
    static = Path("detection/sigma/mappings/attack_navigator_layer.json")
    path = auto if auto.exists() else static
    if not path.exists():
        raise HTTPException(status_code=404, detail="Layer ATT&CK absente")
    return json.loads(path.read_text(encoding="utf-8"))


@app.get("/soar/blocks")
async def soar_blocks():
    return list_blocks()


@app.delete("/soar/blocks/{ip}")
async def soar_unblock(ip: str):
    return {"unblocked": unblock_ip(ip), "ip": ip}


@app.get("/coverage")
async def coverage():
    techniques = {}
    if MAPPING_PATH.exists():
        mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
        for name, spec in mapping.items():
            mitre = spec.get("mitre_attack") or {}
            techniques[mitre.get("technique_id", name)] = {
                "name": mitre.get("technique_name"),
                "tactic": mitre.get("tactic"),
                "scenario": name,
                "sigma": spec.get("sigma_rules"),
            }
    return {"techniques": techniques, "count": len(techniques)}
