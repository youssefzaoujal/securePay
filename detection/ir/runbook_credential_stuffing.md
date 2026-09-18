# Incident Response Runbook: Credential Stuffing
# SecurePay SOC

## 1. Detection

| Field | Value |
|-------|-------|
| **Alert** | SecurePay - Credential Stuffing Attack Detected |
| **Rule ID** | 100200 |
| **Severity** | High |
| **MITRE ATT&CK** | T1110.004 - Credential Stuffing |
| **Target** | Keycloak authentication endpoint |

## 2. Triage

### Questions :
1. Combination d'usernames testés (listes de credential stuffing connues) ?
2. Y a-t-il des succès parmi les échecs ?
3. Les IPs sont-elles TOR/proxy known ?
4. Impact sur les comptes merchants ?

### Commandes :
```bash
# Analyser les tentatives
cat /var/log/securepay/events_$(date +%Y%m%d).jsonl | \
  jq 'select(.scenario == "credential_stuffing")' | \
  jq -s 'group_by(.source_ip) | map({ip: .[0].source_ip, attempts: length, usernames: (map(.username) | unique)})'

# Vérifier les accounts compromis
docker exec securepay-keycloak /opt/keycloak/bin/kcadm.sh get users -r securepay --query.enabled true --fields username,lastLogin
```

## 3. Containment

| Action | Détail |
|--------|--------|
| Bloquer l'IP | WAF firewall-drop |
| Activer progressive delay | Keycloak: brute force protection |
| Reset passwords suspects | Force password change pour accounts ciblés |
| Bloquer les comptes avec logins suspects | Keycloak: désactiver temporairement |

### Progressive Delay Keycloak :
```
Realm Settings → Security Defenses → Brute Force Detection:
  ✓ Enable: True
  Wait Increment: 5 seconds
  Max Wait: 900 seconds (15 min)
  Min Login Failures: 5
  Failure Reset: 15 minutes
```

## 4. Investigation

| Étape | Action |
|-------|--------|
| 1 | Identifier les usernames ciblés |
| 2 | Vérifier si des comptes ont été compromis |
| 3 | Vérifier les lastLogin des comptes concernés |
| 4 | Analyser les sources IP (géolocalisation) |
| 5 | Corréler avec les tentatives de BOLA |

## 5. Recovery

| Action | Détail |
|--------|--------|
| Forcer reset mots de passe | Comptes potentiellement compromis |
| Activer MFA | Pour tous les merchants |
| Audit des sessions actives | Révoquer les sessions suspectes |

## 6. Metrics

| Métrique | Valeur |
|----------|--------|
| Nombre de tentatives | ___ |
| IPs uniques | ___ |
| Comptes compromis | ___ |
| Temps de détection | ___ min |
