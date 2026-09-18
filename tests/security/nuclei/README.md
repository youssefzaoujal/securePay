# Nuclei — templates contre l'API SecurePay (lab)

Pas d'exploits tiers. Cible : votre gateway (`http://localhost:8000`).

```bash
nuclei -t tests/security/nuclei -u http://localhost:8000
```

- `unauth-payments.yaml` — `/payments` sans JWT → 401/403
- `security-headers.yaml` — alerte si `X-Content-Type-Options` manque
