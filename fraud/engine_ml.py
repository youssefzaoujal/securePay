"""Fraud detection engine - Règles heuristiques + ML (Isolation Forest)."""

import os
import numpy as np
from datetime import datetime, timezone
from typing import Optional

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class FraudEngine:
    """Moteur de détection de fraude hybride (règles + ML)."""

    HIGH_AMOUNT_THRESHOLD = 5000.0
    VERY_HIGH_AMOUNT_THRESHOLD = 10000.0

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.scaler = None
        if ML_AVAILABLE and model_path:
            self._load_model(model_path)

    def _load_model(self, path: str):
        """Charger le modèle ML pré-entraîné."""
        model_file = os.path.join(path, "isolation_forest.pkl")
        scaler_file = os.path.join(path, "scaler.pkl")
        if os.path.exists(model_file) and os.path.exists(scaler_file):
            self.model = joblib.load(model_file)
            self.scaler = joblib.load(scaler_file)

    def analyze(
        self,
        amount: float,
        currency: str,
        card_token: str,
        merchant_id: str,
        ip_address: str,
    ) -> dict:
        """Analyser une transaction et retourner un score de risque."""
        flags = []
        total_score = 0.0

        # Règles heuristiques
        score, flag = self._check_amount(amount, currency)
        if flag:
            flags.append(flag)
            total_score += score

        score, flag = self._check_velocity(card_token)
        if flag:
            flags.append(flag)
            total_score += score

        score, flag = self._check_ip_risk(ip_address)
        if flag:
            flags.append(flag)
            total_score += score

        score, flag = self._check_merchant_risk(merchant_id)
        if flag:
            flags.append(flag)
            total_score += score

        # Score ML (si disponible)
        if self.model and self.scaler:
            ml_score = self._ml_score(amount, card_token, merchant_id)
            if ml_score > 0.7:
                total_score += ml_score * 0.4
                flags.append(f"ML anomaly score: {ml_score:.3f}")

        risk_score = min(total_score, 1.0)

        if risk_score < 0.3:
            risk_level, recommendation = "low", "approve"
        elif risk_score < 0.6:
            risk_level, recommendation = "medium", "review"
        elif risk_score < 0.85:
            risk_level, recommendation = "high", "decline"
        else:
            risk_level, recommendation = "critical", "decline"

        return {
            "risk_score": round(risk_score, 4),
            "risk_level": risk_level,
            "flags": flags,
            "recommendation": recommendation,
        }

    def _check_amount(self, amount, currency):
        if amount > self.VERY_HIGH_AMOUNT_THRESHOLD:
            return 0.4, f"Montant très élevé: {amount} {currency}"
        if amount > self.HIGH_AMOUNT_THRESHOLD:
            return 0.2, f"Montant élevé: {amount} {currency}"
        return 0.0, None

    def _check_velocity(self, card_token):
        # TODO: Implémenter la vérification de vélocité via Redis
        return 0.0, None

    def _check_ip_risk(self, ip_address):
        if not ip_address:
            return 0.1, "IP non disponible"
        # TODO: Vérifier IP contre listes noires / VPN / Tor
        return 0.0, None

    def _check_merchant_risk(self, merchant_id):
        # TODO: Vérifier risque du marchand
        return 0.0, None

    def _ml_score(self, amount, card_token, merchant_id):
        """Score ML via Isolation Forest."""
        try:
            features = np.array([[amount, hash(card_token) % 10000, hash(merchant_id) % 100]])
            features_scaled = self.scaler.transform(features)
            prediction = self.model.predict(features_scaled)
            score = self.model.score_samples(features_scaled)[0]
            # Normaliser le score (-1 = anomalie, 1 = normal) vers (0, 1)
            return max(0, min(1, (score + 1) / 2))
        except Exception:
            return 0.0

    def train_model(self, training_data: list[dict]):
        """Entraîner le modèle Isolation Forest sur des données synthétiques."""
        if not ML_AVAILABLE:
            raise RuntimeError("scikit-learn non disponible")

        X = np.array([
            [d["amount"], d.get("velocity", 0), d.get("merchant_risk", 0)]
            for d in training_data
        ])

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
        )
        self.model.fit(X_scaled)

        # Sauvegarder le modèle
        model_path = os.environ.get("FRAUD_MODEL_PATH", "./fraud/models/")
        os.makedirs(model_path, exist_ok=True)
        joblib.dump(self.model, os.path.join(model_path, "isolation_forest.pkl"))
        joblib.dump(self.scaler, os.path.join(model_path, "scaler.pkl"))
