# Incident Response Runbook: Card Testing Attack
# SecurePay SOC

## 1. Detection

| Field | Value |
|-------|-------|
| **Alert** | SecurePay - Card Testing Attack Detected |
| **Rule ID** | 100100 |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1657 - Financial Theft |
| **First seen** | Auto-detected by Wazuh/Sigma |

## 2. Triage

### Questions à se poser :
1. Le traffic est-il légitime (merchant en test) ou hostile ?
2. Combination de cartes différentes depuis une même IP ?
3. Y a-t-il des transactions approuvées parmi les échecs ?
4. Le merchant est-il aware ?

### Données à vérifier :
```bash
# Consulter les logs de l'attaque
cat /var/log/securepay/events_$(date +%Y%m%d).jsonl | \
  jq 'select(.scenario == "card_testing" and .status == "failed")' | \
  jq -s 'group_by(.source_ip) | map({ip: .[0].source_ip, count: length})'

# Vérifier les transactions du merchant
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/merchants/MERCH_001/transactions?status=failed
```

## 3. Containment

| Action | Détail | Responsable |
|--------|--------|-------------|
| Bloquer l'IP au WAF | NGINX: `deny 10.x.x.x;` | SOC Analyst |
| Suspendre le merchant (si complicité) | Keycloak: désactiver le client | Admin |
| Inverser les transactions approuvées | API Payment: POST /refund | Payment Team |

### Commande de blocage :
```bash
# Ajouter au WAF NGINX
echo "deny 10.0.0.5;" >> /etc/nginx/conf.d/blocked_ips.conf
docker exec securepay-nginx nginx -s reload
```

## 4. Investigation

| Étape | Action |
|-------|--------|
| 1 | Identifier la source: IP, User-Agent, timestamps |
| 2 | Corréler avec d'autres alertes (credential stuffing ?) |
| 3 | Vérifier si des données cartes ont été exfiltrées |
| 4 | Rechercher d'autres merchants impactés |
| 5 | Documenter la timeline complète |

## 5. Recovery

| Action | Détail |
|--------|--------|
| Réactiver le merchant | Si faux positif |
| Forcer rotation des clés API | Si compromission suspected |
| Notifier le DPO | Si données personnelles impactées (RGPD) |

## 6. Lessons Learned

| Question | Réponse |
|----------|---------|
| Temps de détection | ___ minutes |
| Temps de containment | ___ minutes |
| Transactions impactées | ___ |
| Montant total | €___ |
| Améliorations | ___ |

## MITRE ATT&CK Mapping

```
T1657 - Financial Theft
  └── TA0040 - Impact
      └── Card Testing / Carding
          └── Detection: Sigma Rule card_testing_attack.yml
              └── Response: Wazuh Active Response (firewall-drop)
```
