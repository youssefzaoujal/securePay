# SOC-as-Code (TheHive, Cortex, OpenCTI)

Par défaut le lab **n'embarque pas** TheHive/OpenCTI (plusieurs Go de RAM). Le connecteur Python écrit des cases JSONL et enrichit via un bundle STIX 2.1 importable.

## Flux

```
Sigma alert → SOAR block IP
            → TheHive case (logs/thehive-cases.jsonl)
            → enrichissement OpenCTI/STIX (detection/intel/stix_bundle.json)
            → layer ATT&CK auto (attack_navigator_layer.auto.json)
```

APIs :

- `POST /evaluate` — alerte + tickets + intel
- `GET /hive/cases`
- `GET /intel`
- `GET /mitre/navigator`

## Brancher un vrai TheHive

```powershell
$env:THEHIVE_URL="http://localhost:9001"
$env:THEHIVE_API_KEY="votre-clé"
```

TheHive 4 a besoin d'Elasticsearch : `docker compose --profile elk up -d` puis un compose TheHive à part (image `thehiveproject/thehive:4.1.24-1`). Cortex analyse les observables (IP) si son URL est configurée côté TheHive — hors scope RAM du lab par défaut.

## OpenCTI

Importer `detection/intel/stix_bundle.json` (Connectors → STIX 2.1 file). Les alertes Sigma dont l'IP/MITRE matche le bundle reçoivent `opencti_matches`.
