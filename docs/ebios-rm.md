# Analyse de risque EBIOS RM (extrait lab)

Méthode **EBIOS Risk Manager** (ANSSI) — atelier pédagogique, pas un dossier ANSSI livré.

## Socle (atelier 1)

- **Métier** : PSP simulé, acceptation de paiements carte de test.
- **Valeurs métier** : disponibilité de l'API, intégrité des captures, confidentialité des PAN.
- **Événements redoutés** : vol de PAN, fraude carding, indisponibilité gateway, rejeu JWT.

## Sources de risque (atelier 2)

| Source | Objectif visé | Scénario lab |
|--------|---------------|--------------|
| Cybercriminel financier | Gains via BIN testing | `card_testing_attack.yml` T1657 |
| Attaquant opportuniste API | IDOR / BOLA | `bola_attack.yml` T1213 |
| Compromission jeton | Session hijack | `jwt_replay.yml` T1550.001 |
| Fuite logs | Exfiltration SAD | `pan_leakage.yml` T1552 |

## Mesures (atelier 5 — extraits)

1. Tokenisation AES-256-GCM, CVV hors persistance.
2. Object-level auth (`shared/bola.py`).
3. Anti-replay `jti`.
4. Sigma + SOAR blocage IP + ticket TheHive.
5. Admission Kyverno + Falco + default-deny.
6. CI qui bloque HIGH/CRITICAL Trivy / Gitleaks.

Les **risques résiduels** restent : lab HTTP (pas TLS sur :8088), Vault `-dev`, Keycloak secrets dans `.env`, TheHive non déployé par défaut.
