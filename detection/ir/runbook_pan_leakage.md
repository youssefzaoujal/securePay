# Incident Response Runbook: PAN Leakage (PCI)

## 1. Detection

Ceci est un **incident PCI**. Un PAN complet dans un log = Req 3 + Req 10 violés.

| Field | Value |
|-------|-------|
| **Sigma** | `pan_leakage.yml` |
| **MITRE** | T1552 |
| **Preventive control** | `shared/redaction.py` + structlog processor |

## 2. Containment (immédiat)

1. Couper le shipping Vector/Filebeat.
2. Purger Loki/S3/Wazuh indexer pour la fenêtre.
3. Rotation `VAULT_MASTER_KEY` via Vault.
4. Ouvrir le registre d'incidents PCI (Req 12.10).

## 3. Lab note

Le pipeline rédige les PAN **avant** écriture. Cette alerte ne doit **jamais**
partir en lab sain — si elle part, le processeur de rédaction a régressé.
