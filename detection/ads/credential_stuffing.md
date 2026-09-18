# ADS — Credential Stuffing

- **Goal** : détecter les tentatives de connexion massives par IP (stuffing).
- **Categorisation** : ATT&CK T1110.004 (Brute Force: Credential Stuffing) — logsource `securepay/auth`.
- **Strategy** : aggregation par `source_ip` sur fenêtre 5 min, seuil 5 échecs `authentication_attempt`.
- **Technical Context** : événements `authentication_attempt` avec `status=failed`.
- **Blind Spots** : distribution par botnet (1/IP), attaque via compte unique.
- **False Positives** : collaborateur oubliant son mot de passe (5 fois/5 min) — contexte IP interne à exclure.
- **Validation** : `test_sigma_rule_quality.py` rejoue 5 échecs → fire ; succès seuls → 0.
- **Priority** : P2.