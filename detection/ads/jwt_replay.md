# ADS — JWT Replay

- **Goal** : détecter la réutilisation d'un `jti` déjà consommé (replay d'un token JWT volé).
- **Categorisation** : ATT&CK T1550.001 (Use Alternate Authentication Material: Application Access Token) — logsource `securepay/auth`.
- **Strategy** : matching simple sur champ + cache mémoire (fenêtre 30 min).
- **Technical Context** : événement `jwt_replay` émis par `shared/auth._reject_replay` avant tout accès.
- **Blind Spots** : replay après expiration mémoire (`_JTI_SEEN`), multi-réplicas sans cache partagé.
- **False Positives** : double envoi légitime de la même requête par un client mal configuré.
- **Validation** : `test_sigma_rules.py::test_jwt_replay_fires_once` — deux usages du même `jti` → un seul fire. Corpus bénin : token unique par requête → 0.
- **Priority** : P1.