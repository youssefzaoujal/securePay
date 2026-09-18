# Purple-team report — Home SOC (ThreatDetect)

Exercice interne : rouge (simulateur) + bleu (Sigma/Wazuh/Falco) sur le réseau Docker `securepay-net`.

## Périmètre

- Cible : SecurePay gateway + Keycloak (pas Juice Shop sauf profil `purple`)
- SIEM : moteur Sigma + Loki/Grafana (défaut) / Elastic `profile elk` / Wazuh `profile siem`
- Atomic equivalent : `detection/simulator/attack_generator.py` (patterns paiement, pas Windows ART)

## Résultats

| Technique | Tentative | Détecté ? | Gap initial | Fix |
|-----------|-----------|-----------|-------------|-----|
| T1657 carding | 25 PAN / IP | Oui (seuil 10/5m) | vélocité fraude était TODO | `FraudEngine._check_velocity` + Sigma |
| T1110.004 stuffing | 25 logins failed | Oui | règle Keycloak `login_error` seulement | sélection `authentication_attempt` |
| T1213 BOLA | 10 GET cross-tenant | Oui (seuil 3) | GET payment 404 sans check | `assert_object_owner` |
| T1550.001 replay | jti réutilisé | Oui | pas d'anti-replay | cache jti + Sigma |
| T1190 SQLi | `' OR 1=1` | Contrôle préventif | n/a | ORM + règle `injection_probe` |
| T1059 shell pod | Falco (lab k8s) | Oui (règle custom) | — | `k8s-security/falco/rules.yml` |

## Couverture ATT&CK Navigator

Fichier : `detection/sigma/mappings/attack_navigator_layer.json`  
Importer sur [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).

## Juice Shop (optionnel)

```powershell
docker compose --profile purple up -d
# http://localhost:3001 — surface web vulnérable à part, pour comparer WAF vs app métier
```

## Conclusion

4/4 scénarios SentinelPay détectés. Réponse auto : IP block TTL 1h. Gaps fermés dans ce repo (pas un rapport théorique).
