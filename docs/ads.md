# Alerting & Detection Strategy (ADS) — SecurePay Detection Engineering

> Cadre utilisé par l'équipe Incident Response de **Palantir** — chaque règle
> Sigma est formalisée avec un *goal*, une stratégie, les angles morts assumés,
> les faux positifs connus et une méthode de validation.

Chaque détection du lab est documentée dans `detection/ads/<rule>.md`

## Structure ADS (Palantir format)

| Section | Contenu attendu |
|---------|-----------------|
| **Goal** | Quel comportement veut-on détecter, en une phrase. |
| **Categorisation** | Mapping MITRE ATT&CK + produit/logsource. |
| **Strategy** | Fill in / threshold / aggregate — comment on détecte. |
| **Technical Context** | Quels événements, quels champs, quels seuils. |
| **Blind Spots & Assumptions** | Ce qu'on ne voit pas, ce qu'on assume. |
| **False Positives** | Où ça va biper à tort. |
| **Validation** | Comment on prouve que ça marche (méthode + commande). |
| **Priority** | Priorisation pour l'analyste (P1-P4). |

## Règles couvertes

| Règle Sigma | Fichier ADS |
|-------------|-------------|
| `jwt_replay` | [jwt_replay.md](detection/ads/jwt_replay.md) |
| `card_testing_attack` | [card_testing_attack.md](detection/ads/card_testing_attack.md) |
| `bola_attack` | [bola_attack.md](detection/ads/bola_attack.md) |
| `credential_stuffing` | [credential_stuffing.md](detection/ads/credential_stuffing.md) |
| `fraud_anomaly` | [fraud_anomaly.md](detection/ads/fraud_anomaly.md) |
| `sql_injection` | [sql_injection.md](detection/ads/sql_injection.md) |
| `pan_leakage` | [pan_leakage.md](detection/ads/pan_leakage.md) |
| `rate_limit_abuse` | [rate_limit_abuse.md](detection/ads/rate_limit_abuse.md) |
| `legacy_cobol_injection` | [legacy_cobol_injection.md](detection/ads/legacy_cobol_injection.md) |
| `legacy_core_declines` | [legacy_core_declines.md](detection/ads/legacy_core_declines.md) |
| `ledger_reconciliation_breakdown` | [ledger_reconciliation_breakdown.md](detection/ads/ledger_reconciliation_breakdown.md) |

## Boucle de validation (CI)

Chaque PR touchant `detection/sigma/rules/` exécute
`tests/unit/test_sigma_rule_quality.py` :
- rejeu du corpus malveillant → la règle **doit** déclencher (zéro silence)
- rejeu du corpus bénin → **zéro** alerte critical/high (faux positifs contrôlés)

C'est le contrat ADS « validation » automatisé.