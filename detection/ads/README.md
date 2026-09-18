# Alerting and Detection Strategy — index

Format inspiré Palantir ADS. Chaque fiche : objectif, MITRE, logsource, détection, faux positifs, tests.

| ADS | Règle Sigma | Technique | Tests |
|-----|-------------|-----------|-------|
| [Card testing](card-testing.md) | `card_testing_attack.yml` | T1657 | `test_sigma_rules.py` |
| BOLA | `bola_attack.yml` | T1213 | seuil 3 denies |
| JWT replay | `jwt_replay.yml` | T1550.001 | 1 event blocked |
| Credential stuffing | `credential_stuffing.yml` | T1110.004 | 5 fails / 60s |
| SQLi probe | `sql_injection.yml` | T1190 | `injection_probe` |
| PAN leak | `pan_leakage.yml` | T1552 | `pan_leakage` |

Les tests unitaires **ne mockent pas** le moteur : ils rejouent des événements JSON contre les YAML réels.
