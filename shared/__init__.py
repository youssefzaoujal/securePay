"""Noyau de sécurité partagé — auth, BOLA, audit, métriques, événements SOC."""

from shared.redaction import redact_secrets

__all__ = ["redact_secrets"]
