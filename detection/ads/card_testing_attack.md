# ADS — Card Testing / Carding

- **Goal** : détecter la validation en masse de PAN (carding) par IP ou par carte.
- **Categorisation** : ATT&CK T1657 (Financial Theft) — logsource `securepay/gateway`.
- **Strategy** : aggregation par IP sur fenêtre 60 s → seuil de 10 échecs `payment_attempt`.
- **Technical Context** : événements `payment_attempt` avec `status=failed` ; groupe `source_ip`.
- **Blind Spots** : carding distribué lent (dormant), rotation d'IP (botnet).
- **False Positives** : client réel en erreur réseau répétée (TPP), tests pré-production sur la même IP.
- **Validation** : `test_sigma_rule_quality` rejoue 11 échecs → fire ; 30 succès bénins → 0.
- **Priority** : P1 — flush du groupe + SOAR block 1h.