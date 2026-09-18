# Zero Trust — modèle appliqué

Principe : **jamais faire confiance au réseau**, authentifier chaque requête, limiter le blast radius.

| Contrôle | Où |
|----------|-----|
| Identité systématique | JWT RS256 JWKS sur gateway, payment, tokenization, fraud |
| Least privilege objet | BOLA : le JWT définit le tenant, pas le body |
| Least privilege réseau | Kubernetes NetworkPolicy default-deny |
| Least privilege compute | Kyverno no-root, drop ALL caps, read-only FS |
| Least privilege secrets | Vault injector, jamais de clé dans ConfigMap |
| Assume breach | Falco runtime + Sigma + SOAR blocage IP |
| Continuous verification | jti anti-replay, rate-limit, 3DS si fraude `review` |

Les NetworkPolicies **ne remplacent pas** l'authN : un pod payment compromis ne détient pas le master key du vault tokenization.
