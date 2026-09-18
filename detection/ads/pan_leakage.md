# ADS — PAN Leakage

- **Goal** : détecter un PAN en clair passé dans un log/événement (violation PCI-DSS Req 3).
- **Categorisation** : ATT&CK T1027 (Obfuscated Files) — logsource `securepay/log`.
- **Strategy** : matching simple `event_type=pan_leakage` (émetteur : `shared/redaction` quand un PAN régénère).
- **Technical Context** : couche de rédaction `_PAN_RE` ; les 4 derniers chiffres sont autorisés.
- **Blind Spots** : PAN chiffrés, PAN en Base64 dans des blobs.
- **False Positives** : numéros de téléphone ≥ 13 chiffres (tronqués mais matchables) — améliorable avec BIN whitelist.
- **Validation** : `test_sql_injection_and_pan_leak_and_stuffing` — fire immédiat.
- **Priority** : P1 — incident de conformité.