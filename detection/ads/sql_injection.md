# ADS — SQL Injection Probe

- **Goal** : détecter les tentatives d'injection SQL dans les paramètres API.
- **Categorisation** : ATT&CK T1190 (Exploit Public-Facing App) / T1059 — logsource `securepay/gateway`.
- **Strategy** : matching simple `event_type=injection_probe` (émis par middleware WAF / détection payload).
- **Technical Context** : payloads type `' OR 1=1 --`, bindings SQLAlchemy côté service.
- **Blind Spots** : injection blind non détectée par signatures, WAF contourné.
- **False Positives** : caractères `'` légitimes dans des champs description (rare).
- **Validation** : `test_sql_injection_and_pan_leak_and_stuffing` — payload capturé → fire immédiat.
- **Priority** : P1.