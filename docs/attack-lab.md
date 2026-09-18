# Attack lab (SentinelPay §7) — réseau Docker isolé uniquement

> Simulation. PAN de test seulement. Jamais de cibles externes.

## Pré-requis

```powershell
docker compose up -d
docker compose --profile app up -d --build
python -m uvicorn dashboard:app --port 9000
```

## Scénarios

| # | Attaque | Comment | Défense | Sigma | SOAR |
|---|---------|---------|---------|-------|------|
| 1 | Credential stuffing | Command Center → SOC | Keycloak brute-force + 429 | `credential_stuffing.yml` T1110.004 | blocage IP |
| 2 | BOLA | `GET /payments/{id}` autre merchant | `shared/bola.py` 403 | `bola_attack.yml` T1213 | blocage IP |
| 3 | Card testing | 25 PAN / même IP | vélocité fraude + rate-limit | `card_testing_attack.yml` T1657 | blocage IP |
| 4 | JWT replay | même `jti` | cache jti 401 | `jwt_replay.yml` T1550.001 | blocage IP |

## Preuve

```powershell
# Générer le trafic
# puis :
curl -X POST http://localhost:8010/evaluate
curl http://localhost:8010/soar/blocks
```

Les IPs bloquées reçoivent **403** au gateway (`RateLimitMiddleware`). TTL 1h. Déblocage : `DELETE /soar/blocks/{ip}`.

Détail purple-team : [`purple-team-report.md`](purple-team-report.md).
