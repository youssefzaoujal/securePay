# Incident Response Runbook: BOLA Attack
# SecurePay SOC

## 1. Detection

| Field | Value |
|-------|-------|
| **Alert** | SecurePay - BOLA Attack Attempt Detected |
| **Rule ID** | 100300 |
| **Severity** | High |
| **MITRE ATT&CK** | T1213 - Data from Information Repositories |
| **OWASP** | API1:2023 - Broken Object Level Authorization |

## 2. Triage

### Questions :
1. Le merchant légitime explore-t-il l'API ou cherche-t-il à accéder à des données ?2. Pattern d'énumération (IDs séquentiels) ?3. Y a-t-il eu succès (données exfiltrées) ?4. Autres endpoints ciblés ?

### Commandes :
```bash
# Analyser le pattern d'accès
cat /var/log/securepay/events_$(date +%Y%m%d).jsonl | \
  jq 'select(.event_type == "authorization_error" and .error_type == "object_level_authorization")' | \
  jq -s 'group_by(.target_merchant_id) | map({target: .[0].target_merchant_id, attempts: length})'

# Vérifier les endpoints ciblés
cat /var/log/securepay/events_$(date +%Y%m%d).jsonl | \
  jq 'select(.scenario == "bola")' | jq -s 'map(.http_path) | group_by(.) | map({path: .[0], count: length})'
```

## 3. Containment

| Action | Détail |
|--------|--------|
| Révoquer la clé API du merchant | Keycloak: régénérer le client_secret |
| Ajouter rate limit strict | NGINX: 5 req/min pour ce merchant |
| Review de tous les accès | Audit log du merchant |

## 4. Investigation

| Étape | Action |
|-------|--------|
| 1 | Identifier le merchant source |
| 2 | Lister toutes les ressources tentées |
| 3 | Vérifier les IDs tentés (énumération ?) |
| 4 | Corréler avec d'autres scénarios |
| 5 | Vérifier l'intégrité des données |

## 5. Recovery

| Action | Détail |
|--------|--------|
| Rotation des clés API | Tous les merchants si needed |
| Audit de la base | Vérifier intégrité données |
| Renforcer le contrôle object-level | Code review du middleware auth |

## MITRE ATT&CK

```
T1213 - Data from Information Repositories
  └── TA0009 - Collection
      └── BOLA / IDOR
          └── Detection: Sigma Rule bola_attack.yml
              └── Response: Keycloak client revocation
```
