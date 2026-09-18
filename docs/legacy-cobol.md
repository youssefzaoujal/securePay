# Core banking COBOL (GnuCOBOL)

SecurePay n'embarque **pas** IBM z/OS. Le service `legacy-core` compile un programme **GnuCOBOL** dans l'image Docker et l'expose via un adapter FastAPI.

```
Gateway → Payment → [mTLS] → wrapper FastAPI → binaire VALIDATE (COBOL)
                                              ↳ solde fictif 500 000 EUR
```

## Contrôles

| Contrôle | Implémentation |
|----------|----------------|
| Isolation | Le wrapper n'a **pas** de DATABASE_URL. Calcul uniquement. |
| Anti-injection | `legacy_core/sanitize.py` — `account_id` `[A-Z0-9]{1,10}`, amount borné, `subprocess` **sans** `shell=True` |
| Rate-limit | 30 req/min (protection « mainframe ») |
| mTLS | Compose profile `app` : CA lab + cert client `payment` (`legacy_core/certs.py`) |
| NetworkPolicy | `k8s-security/network-policies/legacy-core.yml` — **seul** `payment` parle au pod |

## Démo

```powershell
docker compose --profile app up -d --build
# Command Center → carte « Core COBOL » : 100 EUR APPROVED, 600 000 EUR DECLINED
```

Variables : `LEGACY_CORE_URL`, `LEGACY_CORE_CA`, `LEGACY_CORE_CERT`, `LEGACY_CORE_KEY`.
