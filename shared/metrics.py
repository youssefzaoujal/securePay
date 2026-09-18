"""Métriques Prometheus — volume, fraude, latence, décisions 3DS."""

from prometheus_client import Counter, Histogram, Gauge, CONTENT_TYPE_LATEST, generate_latest

TRANSACTIONS = Counter(
    "securepay_transactions_total",
    "Transactions traitées",
    ["status", "merchant_id", "decision"],
)
FRAUD_SCORE = Histogram(
    "securepay_fraud_score",
    "Distribution des scores de fraude",
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.85, 0.95, 1.0),
)
REQUEST_LATENCY = Histogram(
    "securepay_request_latency_seconds",
    "Latence des requêtes HTTP",
    ["service", "route", "method"],
)
BOLA_BLOCKS = Counter(
    "securepay_bola_blocks_total",
    "Tentatives BOLA bloquées",
)
RATE_LIMIT_HITS = Counter(
    "securepay_rate_limit_hits_total",
    "Requêtes 429",
)
ACTIVE_CHALLENGES = Gauge(
    "securepay_3ds_challenges_active",
    "Challenges 3DS2 en cours",
)
DETECTION_ALERTS = Counter(
    "securepay_detection_alerts_total",
    "Alertes Sigma émises",
    ["rule", "severity", "mitre"],
)
SIGMA_EVAL_SECONDS = Histogram(
    "securepay_sigma_eval_seconds",
    "Durée d'évaluation Sigma",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
SOAR_BLOCKS = Gauge(
    "securepay_soar_blocks",
    "IP actuellement bloquées par le SOAR",
)


def metrics_response() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
