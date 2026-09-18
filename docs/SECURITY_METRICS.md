# SECURITY_METRICS — SecurePay

> Généré automatiquement : `python -m scripts.security_metrics` — 2026-09-04T19:05:34.047661+00:00

## Règle de reporting

Chaque chiffre ci-dessous provient d'une mesure instrumentée du lab et
**peut être justifié en entretien**. On ne publie jamais un chiffre non mesuré.

## Moteur de fraude (format type Adyen Protect)

| Métrique | Valeur | Corpus (simulé) |
|----------|--------|-----------------|
| Taux de détection (recall) | 60.0% | 2000 transactions labelsées |
| Taux de faux positifs (FPR) | 1.6% | 1855 bénin |
| — dont hard-block (refus sans SCA) | 1.6% | refus net d'un bénin |
| — dont friction SCA (résolu) | 0.0% | un challenge 3DS le résout |
| Precision | 74.4% | — |
| F1 | 66.4% | — |

Interprétation (ancien vs nouveau vocabulaire) :
« Le moteur (vélocité + Isolation Forest) détecte X% de la fraude simulée
avec Y% de faux positifs, dans le même format que le reporting Adyen Protect. »

## Détection (Sigma-as-code)

| Métrique | Valeur |
|----------|--------|
| Règles chargées | 11 |
| MTTD moyen (rejeu par frame) | 0.039 ms |
| Alertes déclenchées sur probe joué : replay | 50 |
| Latence blocage SOAR (block ip) | 106.375 ms |

## Couverture ATT&CK (purple-team)

| Technique | Tactic | Règle | Statut en lab |
|-----------|--------|-------|---------------|
| T1657 Financial Theft | TA0040 Impact | card_testing, fraud_anomaly, ledger_reconciliation | Détectée |
| T1550.001 Application Access Token | TA0008 Lateral | jwt_replay | Détectée |
| T1213 Data from Info Repos | TA0009 Collection | bola_attack | Détectée |
| T1110.004 Credential Stuffing | TA0006 Cred | credential_stuffing | Détectée |
| T1190 Exploit Public-Facing | TA0001 Init | sql_injection | Détectée |

## Historisation

Conserver ce fichier versionné + le JSON brut (`--json`) pour montrer une
tendance dans le temps. Un chiffre régressé (ex: détection ↓) déclenche
une revue du moteur — c'est le comportement d'un programme, pas d'une démo.