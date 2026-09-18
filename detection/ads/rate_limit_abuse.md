# ADS — Rate Limit Abuse

- **Goal** : détecter l'abus systématique des limites de débit (pré-DoS, scraping).
- **Categorisation** : ATT&CK T1499 (Endpoint Denial of Service) — logsource `securepay/gateway`.
- **Strategy** : aggregation 429 par IP sur fenêtre 10 min, seuil 12.
- **Technical Context** : événements `rate_limit_exceeded` émis par `gateway/middleware.py`.
- **Blind Spots** : répartition multi-IP, abuse lent sous le seuil.
- **False Positives** : spike légitime (campagne, flash sale) — à corréler avec volumes marchand.
- **Validation** : `test_sigma_rule_quality.py` rejoue 12 events → fire ; bénin → 0.
- **Priority** : P2 → SOAR block 30 min.