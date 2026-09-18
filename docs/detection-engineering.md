# Detection Engineering

Moteur : `detection/engine/sigma_engine.py` (Sigma-lite : égalité, comparateurs, fenêtre, seuil).

Règles : `detection/sigma/rules/*.yml`  
Mapping : `detection/sigma/mappings/mitre_attack.json`  
Runbooks : `detection/ir/`  
Wazuh : `detection/wazuh/` (profil compose `siem`)

Ingestion : chaque service appelle `shared.events.emit_event` → `logs/securepay-events.jsonl`.

```bash
curl -X POST http://localhost:8010/evaluate
curl http://localhost:8010/coverage
curl http://localhost:8010/alerts
curl http://localhost:8010/hive/cases
curl http://localhost:8010/intel
curl http://localhost:8010/mitre/navigator
```

SOC-as-Code : [`docs/soc-as-code.md`](soc-as-code.md).
