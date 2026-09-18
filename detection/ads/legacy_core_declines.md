# ADS — Legacy Core Declines Burst

- **Goal** : détecter une rafale de déclins du core banking (COBOL) — signe de fraude en continue ou incident core.
- **Categorisation** : ATT&CK T1657 (Financial Theft) — logsource `securepay/payment`.
- **Strategy** : aggregation sur `payment_attempt` avec `legacy_core=DECLINED`, fenêtre 10 min, seuil 10.
- **Technical Context** : événements émis par `payment/routes.py` quand `call_legacy_core` retourne DECLINED.
- **Blind Spots** : core down → None (traité par `legacy_core_declines` fail-open lab), décisions au-dessus de la fenêtre.
- **False Positives** : incident core temporaire → pic de déclins bénin (le titre doit distinguer `burst`).
- **Validation** : rejeu 11 déclins → fire ; succès seuls → 0.
- **Priority** : P2.