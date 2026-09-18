# Incident Response Runbook: SQL Injection Probe

## 1. Detection

| Field | Value |
|-------|-------|
| **Alert** | SQLi probe |
| **Sigma** | `sql_injection.yml` |
| **MITRE** | T1190 |
| **Control** | SQLAlchemy ORM, bound parameters, WAF CRS |

## 2. Why this should never succeed

SecurePay n'assemble **jamais** de SQL par interpolation. Les tests
`tests/security/test_injection.py` envoient `' OR 1=1 --` et attendent 422/403,
pas 200.

## 3. Containment

- Confirmer l'absence de `sqlalchemy.exc` dans les logs.
- Ajouter le payload à une règle CRS custom si répété.
- Bloquer l'IP.
