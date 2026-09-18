# ADS — BOLA / Cross-Merchant Access

- **Goal** : détecter les tentatives d'accès object-level cross-tenant (BOLA/IDOR).
- **Categorisation** : ATT&CK T1213 (Exploitation of Remote Services / Data from Info Repos) — logsource `securepay/gateway`.
- **Strategy** : matching simple sur `event_type=authorization_error` + `error_type=object_level_authorization`, agrégation par IP (3 occurrences).
- **Technical Context** : émis par `shared/bola.assert_object_owner` et `bind_merchant_id` (403).
- **Blind Spots** : BOLA réussi (sans erreur) — couvert par la logique appliquée en amont ; énumération lente < 3/fenêtre.
- **False Positives** : bug de mise en cache côté SDK client revoyant une requête cross-tenant légitime.
- **Validation** : `test_sigma_rules.py::test_bola_threshold_and_mitre` — 3 events → fire T1213 ; corpus bénin scopé merchant → 0.
- **Priority** : P1.