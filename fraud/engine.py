"""Moteur de fraude hybride : vélocité (carding) + règles + Isolation Forest."""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from typing import Optional

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    np = None  # type: ignore


class FraudEngine:
    HIGH_AMOUNT_THRESHOLD = 5000.0
    VERY_HIGH_AMOUNT_THRESHOLD = 10000.0
    VELOCITY_WINDOW = 60.0
    CARDING_UNIQUE_CARDS = 5
    CARD_VELOCITY = 8
    IP_VELOCITY = 20
    TOR_HINTS = ("10.255.", "192.0.2.", "198.51.100.")

    def __init__(self, model_path: Optional[str] = None, clock=None):
        self.model = None
        self.scaler = None
        self._by_card: dict[str, deque] = defaultdict(deque)
        self._by_ip: dict[str, deque] = defaultdict(deque)
        self._cards_by_ip: dict[str, dict[str, float]] = defaultdict(dict)
        self._clock = clock if clock is not None else time.time
        if ML_AVAILABLE and model_path:
            self._load_model(model_path)

    def _load_model(self, path: str) -> None:
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
        flags: list[str] = []
        total_score = 0.0

        for score, flag in (
            self._check_amount(amount, currency),
            self._check_velocity(card_token, ip_address),
            self._check_ip_risk(ip_address),
            self._check_merchant_risk(merchant_id),
            self._check_amount_round(amount),
        ):
            if flag:
                flags.append(flag)
                total_score += score

        if self.model is not None and self.scaler is not None:
            ml_score = self._ml_score(amount, card_token, merchant_id)
            if ml_score > 0.7:
                total_score += ml_score * 0.35
                flags.append(f"ML anomaly score: {ml_score:.3f}")

        risk_score = round(min(total_score, 1.0), 4)
        if risk_score < 0.3:
            risk_level, recommendation = "low", "approve"
        elif risk_score < 0.6:
            risk_level, recommendation = "medium", "review"
        elif risk_score < 0.85:
            risk_level, recommendation = "high", "decline"
        else:
            risk_level, recommendation = "critical", "decline"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "flags": flags,
            "recommendation": recommendation,
            "challenge_required": recommendation == "review",
        }

    def _prune(self, bucket: deque) -> None:
        cutoff = self._clock() - self.VELOCITY_WINDOW
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    def _check_velocity(self, card_token: str, ip_address: str):
        now = self._clock()
        card_q = self._by_card[card_token]
        ip_q = self._by_ip[ip_address or "unknown"]
        card_q.append(now)
        ip_q.append(now)
        self._prune(card_q)
        self._prune(ip_q)

        ip = ip_address or "unknown"
        self._cards_by_ip[ip][card_token] = now
        expired = [tok for tok, ts in self._cards_by_ip[ip].items() if now - ts > self.VELOCITY_WINDOW]
        for tok in expired:
            self._cards_by_ip[ip].pop(tok, None)
        unique_cards = len(self._cards_by_ip[ip])

        if unique_cards >= self.CARDING_UNIQUE_CARDS:
            return 0.55, f"Card testing: {unique_cards} cartes distinctes depuis {ip}"
        if len(card_q) >= self.CARD_VELOCITY:
            return 0.35, f"Vélocité carte: {len(card_q)} tx / {int(self.VELOCITY_WINDOW)}s"
        if len(ip_q) >= self.IP_VELOCITY:
            return 0.4, f"Vélocité IP: {len(ip_q)} tx / {int(self.VELOCITY_WINDOW)}s"
        return 0.0, None

    def _check_amount(self, amount, currency):
        if amount > self.VERY_HIGH_AMOUNT_THRESHOLD:
            return 0.65, f"Montant très élevé: {amount} {currency}"
        if amount > self.HIGH_AMOUNT_THRESHOLD:
            return 0.35, f"Montant élevé: {amount} {currency}"
        return 0.0, None

    def _check_amount_round(self, amount: float):
        if amount >= 1000 and float(amount).is_integer():
            return 0.05, "Montant rond élevé (indicateur faible)"
        return 0.0, None

    def _check_ip_risk(self, ip_address):
        if not ip_address:
            return 0.1, "IP non disponible"
        if any(ip_address.startswith(prefix) for prefix in self.TOR_HINTS):
            return 0.25, "IP à risque (plage lab/Tor simulée)"
        return 0.0, None

    def _check_merchant_risk(self, merchant_id):
        if merchant_id in {"MERCH_HIGH_RISK", "merchant-risky"}:
            return 0.2, "Merchant catégorie à risque"
        return 0.0, None

    def _ml_score(self, amount, card_token, merchant_id):
        try:
            velocity = len(self._by_card.get(card_token, []))
            features = np.array([[amount, velocity, hash(merchant_id) % 100]])
            features_scaled = self.scaler.transform(features)
            raw = self.model.score_samples(features_scaled)[0]
            return max(0.0, min(1.0, 1.0 - ((raw + 0.5) / 1.5)))
        except Exception:
            return 0.0

    def train_model(self, training_data: list[dict]):
        if not ML_AVAILABLE:
            raise RuntimeError("scikit-learn non disponible")
        X = np.array(
            [
                [d["amount"], d.get("velocity", 0), d.get("merchant_risk", 0)]
                for d in training_data
            ]
        )
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.model.fit(X_scaled)
        model_path = os.environ.get("FRAUD_MODEL_PATH", "./fraud/models/")
        os.makedirs(model_path, exist_ok=True)
        joblib.dump(self.model, os.path.join(model_path, "isolation_forest.pkl"))
        joblib.dump(self.scaler, os.path.join(model_path, "scaler.pkl"))
