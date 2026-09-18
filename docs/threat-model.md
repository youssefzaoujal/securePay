# Threat Model - SecurePay (STRIDE)

## Méthodologie

Analyse STRIDE appliquée au flux de transaction SecurePay.

## Périmètre

```
Client (Merchant) → API Gateway → Payment Service → Tokenization Service
                                        ↓
                                  Fraud Service → 3DS2 Challenge
                                        ↓
                                   PostgreSQL (vault)
```

---

## 1. Spoofing (Usurpation d'identité)

| Menace | Impact | Contrôle implémenté |
|--------|--------|---------------------|
| Client falsifie un token JWT | Critique | Validation JWT via Keycloak (RSA signature), middleware FastAPI |
| Client utilise un token expiré | Élevé | Vérification `exp` claim, TTL 30min |
| Appel inter-service sans auth | Élevé | MTLS entre services + token propagation |
| Usurpation de merchant_id | Élevé | Le merchant_id est extrait du JWT (pas du body), RBAC |

## 2. Tampering (Falsification de données)

| Menace | Impact | Contrôle implémenté |
|--------|--------|---------------------|
| Modification du montant en transit | Élevé | TLS ≥ 1.2 obligatoire, 1.3 préféré (PCI-DSS Req 4) |
| Falsification du PAN avant tokenisation | Critique | Coffre AES-256-GCM (nonce 96 bits), CVV jamais stocké |
| Injection SQL dans les requêtes | Élevé | SQLAlchemy ORM (pas de SQL brut), paramètres liés |
| Modification du status de transaction | Élevé | Contrôle d'accès object-level (merchant ne voit que ses transactions) |

## 3. Repudiation (Répudiation)

| Menace | Impact | Contrôle implémenté |
|--------|--------|---------------------|
| Négation d'une transaction effectuée | Élevé | Audit logs (PCI-DSS Req 10), correlation_id, timestamp |
| Modification des logs | Élevé | Logs centralisés S3 avec versioning + encryption |
| Absence de traçabilité | Élevé | Chaque requête a un correlation_id unique |

## 4. Information Disclosure (Divulgation d'informations)

| Menace | Impact | Contrôle implémenté |
|--------|--------|---------------------|
| PAN exposé dans les logs | Critique | PAN jamais loggé, seuls les 4 derniers chiffres |
| PAN exposé dans la base | Critique | Tokenisation: PAN chiffré dans vault séparé |
| Erreurs détaillées exposées | Élevé | Messages d'erreur génériques en production |
| Fuite de secrets | Critique | Vault/AWS Secrets Manager, jamais dans le code |
| Données en transit interceptées | Élevé | TLS ≥ 1.2 avec cipher suites fortes |

## 5. Denial of Service (Déni de service)

| Menace | Impact | Contrôle implémenté |
|--------|--------|---------------------|
| Rate limiting dépassé | Élevé | Rate limiting 60 req/min par IP + burst |
| Attaque par chargement | Élevé | Limitation de taille des requêtes (NGINX client_max_body_size) |
| DDoS sur l'API | Élevé | WAF (ModSecurity + OWASP CRS), CDN |
| Saturation DB | Élevé | Connection pooling (20 connections max) |

## 6. Elevation of Privilege (Élévation de privilèges)

| Menace | Impact | Contrôle implémenté |
|--------|--------|---------------------|
| Merchant accède aux données admin | Élevé | RBAC avec rôles: admin, merchant, viewer |
| BOLA (Broken Object Level Authorization) | Élevé | Filtre merchant_id sur toutes les queries |
| Accès au vault sans autorisation | Critique | Vault séparé, accès restreint aux services autorisés |
| Exécution de code via injection | Élevé | Pas d'eval(), pas de shell injection possible |

---

## Scénarios d'attaque testés en lab

| # | Scénario | Résultat attendu |
|---|----------|------------------|
| 1 | BOLA `GET /payments/{id}` cross-merchant | HTTP 403 + event `authorization_error` |
| 2 | Body `merchant_id` ≠ JWT | HTTP 403 (spoofing) |
| 3 | JWT `jti` rejoué | HTTP 401 |
| 4 | `' OR 1=1 --` dans merchant_id | string bindée, pas d'exécution SQL |
| 5 | Carding 25 PAN / même IP | score vélocité ↑ + Sigma T1657 |
| 6 | PAN dans un log structuré | rédigé `****1111` avant écriture |


| Req | Description | Statut |
|-----|-------------|--------|
| 1-2 | Segmentation réseau | VPC + Security Groups |
| 3 | Ne pas stocker de données sensibles | Tokenisation + chiffrement |
| 4 | Chiffrement des données en transit | TLS ≥ 1.2 (1.3 préféré) |
| 6 | Développement sécurisé | SAST, DAST, dependency scan |
| 7 | Contrôle d'accès | RBAC + object-level |
| 8 | Authentification forte | Keycloak + MFA requis (PCI-DSS v4.0.1 Req 8.4.2) |
| 10 | Journalisation | Audit logs + JSON structuré |
| 11 | Tests de sécurité | Trivy, OWASP ZAP, Bandit |
| 12 | Politiques documentées | Ce document + README |
