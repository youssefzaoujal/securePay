"""Tests unitaires - Fraud detection engine."""

import pytest
from fraud.engine import FraudEngine


class TestFraudEngine:
    """Tests pour le moteur de détection de fraude."""

    def setup_method(self):
        self.engine = FraudEngine()

    def test_low_amount_returns_low_risk(self):
        result = self.engine.analyze(
            amount=50.0,
            currency="EUR",
            card_token="tok_test123",
            merchant_id="MERCH_001",
            ip_address="192.168.1.1",
        )

        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "low"
        assert result["recommendation"] == "approve"

    def test_high_amount_returns_medium_risk(self):
        result = self.engine.analyze(
            amount=7500.0,
            currency="EUR",
            card_token="tok_test123",
            merchant_id="MERCH_001",
            ip_address="192.168.1.1",
        )

        assert result["risk_score"] > 0.0
        assert result["risk_score"] < 1.0
        assert any("Montant élevé" in f for f in result["flags"])

    def test_very_high_amount_returns_critical_risk(self):
        result = self.engine.analyze(
            amount=15000.0,
            currency="EUR",
            card_token="tok_test123",
            merchant_id="MERCH_001",
            ip_address="192.168.1.1",
        )

        assert result["risk_score"] >= 0.4
        assert result["risk_level"] in ("high", "critical")
        assert any("Montant très élevé" in f for f in result["flags"])

    def test_missing_ip_adds_risk(self):
        result = self.engine.analyze(
            amount=100.0,
            currency="EUR",
            card_token="tok_test123",
            merchant_id="MERCH_001",
            ip_address="",
        )

        assert any("IP non disponible" in f for f in result["flags"])

    def test_recommendation_thresholds(self):
        # Approuver les petits montants
        result = self.engine.analyze(10.0, "EUR", "tok", "MERCH", "192.168.1.1")
        assert result["recommendation"] == "approve"

        # Revoir les montants moyens
        result = self.engine.analyze(6000.0, "EUR", "tok", "MERCH", "192.168.1.1")
        assert result["recommendation"] in ("review", "decline")
