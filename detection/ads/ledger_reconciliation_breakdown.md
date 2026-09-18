# ADS — Ledger Double-Entry Breakdown

- **Goal** : détecter tout déséquilibre de partie double (delta ≠ 0) ou drift de capture — anomalie d'intégrité financière.
- **Categorisation** : ATT&CK T1657 (Financial Theft) — logsource `securepay/payment-ledger`.
- **Strategy** : matching simple, 1 occurrence = alerte critical (une écriture non balancée suffit).
- **Technical Context** : émis par `payment/ledger.reconcile()` (écart débits≠crédits) et `scripts/reconcile_ledger.py` (drift captures service vs ledger).
- **Blind Spots** : écritures annulées dans la même fenêtre, montants arrondis < 0,01 (tolérance).
- **False Positives** : aucun attendu en partie double saine ; seul un drift de devises croisées peut biper (normalisé).
- **Validation** : `test_sigma_rule_quality.py::test_ledger_reconciliation_rule_fires` ; corpus bénin `delta: 0` → 0.
- **Priority** : P1 — gèle les paiements marchand si confirmé.