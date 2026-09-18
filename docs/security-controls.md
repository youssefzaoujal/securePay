# Security Controls - SecurePay

## Liste des contrôles de sécurité implémentés

### 1. Chiffrement et protection des données

| Contrôle | Détail | PCI-DSS |
|----------|--------|---------|
| Tokenisation PAN | PAN chiffré AES-256-GCM, nonce 96 bits ; **CVV jamais stocké** (Req 3.2.2) | Req 3.4 / 3.2 |
| Chiffrement au repos | RDS encryption enabled (AES-256), Vault entries chiffrées | Req 3.4 |
| Chiffrement en transit | TLS ≥ 1.2, 1.3 préféré (`ssl_protocols TLSv1.2 TLSv1.3` NGINX) + suites fortes, HSTS | Req 4.1 |
| Hachage sécurisé | PBKDF2 pour les mots de passe | Req 8.2 |

### 2. Authentification et autorisation

| Contrôle | Détail | PCI-DSS |
|----------|--------|---------|
| OAuth2/OIDC | Keycloak avec client_credentials et authorization_code+PKCE | Req 8.3 |
| JWT validation | Vérification signature RSA via Keycloak | Req 8.3 |
| RBAC | Rôles: admin, merchant, viewer | Req 7.1 |
| Object-level auth | Merchant ne voit que ses propres transactions | Req 7.1 |
| MFA requis | Tous accès (console + non-console) au périmètre CDE — PCI-DSS v4.0.1 Req 8.4.2 (devenu obligatoire mars 2025) | Req 8.4.2 |
| Brute force protection | 5 tentatives max, lockout 15min | Req 8.1 |
| Password policy | 12+ chars, majuscules, minuscules, chiffres, spéciaux | Req 8.2 |

### 3. Sécurité réseau

| Contrôle | Détail | PCI-DSS |
|----------|--------|---------|
| Segmentation réseau | VPC privé, sous-réseaux public/privé | Req 1.2 |
| Security Groups | Règles minimales par port/service | Req 1.2 |
| Rate limiting | 60 req/min par IP, burst=20 | Req 6.6 |
| WAF | ModSecurity + OWASP CRS | Req 6.6 |
| Security headers | HSTS, CSP, X-Frame-Options, etc. | - |

### 4. Journalisation et audit

| Contrôle | Détail | PCI-DSS |
|----------|--------|---------|
| Structured logging | JSON avec correlation_id | Req 10.2 |
| Audit trail | Table audit_logs avec event_type, user, action, result | Req 10.1 |
| Log centralization | S3 bucket avec versioning et encryption | Req 10.5 |
| Ne pas logger les PAN | PAN jamais dans les logs | Req 10.2 |
| **Revue de logs automatisée (10.4.1.1)** | Moteur Sigma (12 règles) évalue le flux JSONL en continu ; revue manuelle non suffisante — réponse directe à la nouvelle exigence PCI-DSS v4.0.1 | Req 10.4.1.1 |

### 5. Sécurité du code

| Contrôle | Détail | PCI-DSS |
|----------|--------|---------|
| SAST | Bandit + Ruff (analyse statique) | Req 6.1 |
| Dependency scan | pip-audit + Snyk | Req 6.2 |
| Container scan | Trivy (vulnérabilités images) | Req 6.2 |
| Code review | PR requis, 2 approvals | Req 6.4 |

### 6. Infrastructure

| Contrôle | Détail | PCI-DSS |
|----------|--------|---------|
| IaC | Terraform pour toute l'infrastructure | Req 2.2 |
| Container security | ReadOnly filesystem, non-root user | Req 2.2 |
| Secrets management | AWS Secrets Manager / Vault | Req 2.1 |
| Patch management | Images mises à jour régulièrement | Req 6.3 |

### 7. Tests de sécurité

| Contrôle | Détail | PCI-DSS |
|----------|--------|---------|
| Pentest manuel | OWASP ZAP pour tests DAST | Req 11.3 |
| Automated testing | CI/CD avec scans automatisés | Req 11.2 |
| Fraud simulation | Tests avec données frauduleuses synthétiques | - |
