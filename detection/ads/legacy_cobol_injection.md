# ADS — Legacy COBOL Injection

- **Goal** : détecter les payloads suspects rejetés par le wrapper COBOL (sanitization).
- **Categorisation** : ATT&CK T1190 / T1335 (Legacy exploitation) — logsource `securepay/legacy-core`.
- **Strategy** : matching simple `event_type=legacy_core_injection` (émis par `legacy_core/sanitize.py`).
- **Technical Context** : wrapper `subprocess` sans `shell=True`, `account_from_merchant` rejette les octets non alphanumériques.
- **Blind Spots** : injection via des champs non validés par le legacy (amount).
- **False Positives** : account ID champ libre avec accents (rejeté par design).
- **Validation** : `test_legacy_core.py` — payload `'; DROP TABLE` → fire.
- **Priority** : P1.