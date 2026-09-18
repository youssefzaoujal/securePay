# ADS — Fraud Score Anomaly

- **Goal** : détecter les clusters de scores fraude élevés (fraude coordonnée).
- **Categorisation** : ATT&CK T1657 (Financial Theft) — logsource `securepay/fraud-engine`.
- **Strategy** : aggregation sur `risk_score >= 0.85`, fenêtre 15 min, seuil 5.
- **Technical Context** : événements `fraud_score` émis par `fraud/routes.py`.
- **Blind Spots** : fraude "silencieuse" (score < 0.85), un seul événement critique isolé.
- **False Positives** : pic légitime à fort montant (soldes, événements) — à corréler avec `fraud_anomaly` merchant.
- **Validation** : `test_fraud_anomaly_needs_cluster` — 5 events → fire ; ≤ 4 → 0.
- **Priority** : P1 → suspends le merchant temporairement.