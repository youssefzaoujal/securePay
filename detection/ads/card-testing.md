# ADS — Card testing / BIN attack (T1657)

## Goal

Détecter une campagne de **card testing** (beaucoup d’autorisations échouées, même IP, fenêtre courte) avant que le marchand ne subisse des chargebacks.

## Categorization

- MITRE ATT&CK : **T1657 Financial Theft** (Impact)
- PCI-DSS inspiré : Req 10 (audit) + Req 11 (détection)
- Data source : `logs/securepay-events.jsonl` (`event_type=payment_attempt`, `status=failed`)

## Strategy abstract

1. Compter les `payment_attempt` failed par `source_ip` sur 5 minutes.
2. Seuil **10** → alerte critique Sigma.
3. SOAR : blocage IP 1h → gateway 403.
4. Ticket TheHive + enrichissement STIX.

## Blind spots / false positives

- Marchand en recette qui rejoue des PAN de test.
- IP NAT partagée (plusieurs clients légitimes).
- Mitigation : correlér `merchant_id` + vélocité fraude applicative.

## Validation

```powershell
python -m pytest tests/unit/test_sigma_rules.py::test_carding_fires_at_threshold_not_before -q
python -m detection.simulator.attack_generator --scenario carding --attempts 25
curl -X POST http://localhost:8010/evaluate
```

9 échecs → pas d’alerte. 10e → T1657 + SOAR.
