# OWASP API Top 10 (2023) — mapping SecurePay

| ID | Risque | Contrôle dans ce repo | Test |
|----|--------|------------------------|------|
| API1 BOLA | Accès objet d'un autre merchant | `shared/bola.py`, merchant_id JWT | `tests/unit/test_bola.py` |
| API2 Broken auth | JWT faible / replay | JWKS RS256, jti, TTL 30 min | auth + `jwt_replay.yml` |
| API3 BOPLA | Trop de champs | schémas Pydantic, pas de PAN en réponse payment | tokenization tests |
| API4 Unrestricted resource | Carding | rate-limit + vélocité | fraud engine + nginx |
| API5 BFLA | Escalade rôle | `require_role` / scopes | merchants admin-only |
| API6 Business flow | 3DS bypass | challenge_required si review | fraud + 3DS |
| API7 SSRF | URL webhook ouverte | webhook HMAC + allowlist lab | `test_webhooks.py` |
| API8 Misconfig | CORS / headers | security headers middleware, TLS 1.3 | nginx.conf |
| API9 Inventory | APIs fantômes | OpenAPI lab-only, pas de docs en prod | gateway `docs_url` |
| API10 Unsafe consumption | Services internes | NetworkPolicy default-deny, pas de PAN vers payment | k8s-security |

Zero Trust : chaque hop authentifie (JWT inter-service), pas de confiance réseau (NetPol deny).
Voir [`zero-trust.md`](zero-trust.md).
