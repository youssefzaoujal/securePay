# Comment SecurePay attrape un carding en temps réel

> Lab uniquement. PAN de test `4111111111111111`. Aucune donnée carte réelle.

Un recruteur fintech veut souvent **une histoire**, pas une liste d’outils. Voici le scénario que SecurePay rejoue.

## L’attaque

Un attaquant teste des PAN (souvent volés) par petites autorisations, depuis une même IP, pour trouver les cartes encore valides. C’est du **card testing** (MITRE **T1657**). Industriellement : des milliers de tentatives, des montants faibles, un fort taux d’échec.

Dans le Command Center : onglet SOC → **Card testing (T1657)** → Lancer. Le simulateur écrit 25 `payment_attempt` `failed` dans le JSONL.

## Ce que l’application fait déjà

Avant le SOC, la gateway refuse le brute-force (rate-limit) et le moteur fraude compte la **vélocité** carte/IP. Ce n’est pas suffisant : un attaquant lent passe sous le radar applicatif. D’où la détection asynchrone.

## Ce que le SOC fait

La règle Sigma `card_testing_attack.yml` dit : *10 échecs, même IP, 5 minutes*. Le moteur (`detection/engine/sigma_engine.py`) n’est pas un SIEM magique — c’est du **Sigma-as-code** versionné, testé unitairement (9 événements = silence, 10e = alerte).

L’alerte déclenche le SOAR : l’IP entre dans la blocklist. Le middleware gateway la refuse en **403**, *avant* le rate-limit Redis. Un ticket TheHive JSONL est ouvert, la layer ATT&CK se régénère.

## Pourquoi c’est crédible en PFE

- La détection est **mappée MITRE** et documentée en ADS (`detection/ads/card-testing.md`).
- On **attaque son propre lab**, on ne raconte pas une slide.
- La réponse est automatique, mesurable (`GET /soar/blocks`), réversible.

Prochaine lecture : [`docs/attack-lab.md`](../attack-lab.md) et [`docs/purple-team-report.md`](../purple-team-report.md).
