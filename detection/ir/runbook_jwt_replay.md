# Incident Response Runbook: JWT Replay / Tampering

## 1. Detection

| Field | Value |
|-------|-------|
| **Alert** | JWT replay blocked |
| **Sigma** | `jwt_replay.yml` |
| **MITRE** | T1550.001 Application Access Token |
| **Control** | `jti` cache in `shared/auth.py` |

## 2. Triage

1. Le `jti` a-t-il été rejoué depuis la même IP ou un hop différent ?
2. Le token est-il encore dans sa fenêtre `exp` ?
3. Y a-t-il aussi des tentatives de `alg=none` / kid inconnu (logs 401) ?

## 3. Containment

- Révoquer le client OAuth2 Keycloak (`merchant-api` ou le client visé).
- Bloquer l'IP source au WAF NGINX.
- Forcer une rotation du `client_secret`.

## 4. Recovery

- Réémettre des credentials au merchant via un canal hors bande.
- Vérifier qu'aucune transaction `succeeded` n'utilise le même `correlation_id` que les replay.
