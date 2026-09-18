"""Train fraud detection model with synthetic data."""

import os
import sys
import random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fraud.engine import FraudEngine


def generate_synthetic_data(n_samples: int = 10000) -> list[dict]:
    """Générer des données synthétiques pour l'entraînement."""
    data = []

    for _ in range(n_samples):
        # Transactions normales (90%)
        if random.random() < 0.9:
            data.append({
                "amount": random.uniform(1, 1000),
                "velocity": random.randint(0, 5),
                "merchant_risk": random.uniform(0, 0.3),
                "is_fraud": False,
            })
        # Transactions frauduleuses (10%)
        else:
            data.append({
                "amount": random.uniform(500, 50000),
                "velocity": random.randint(5, 50),
                "merchant_risk": random.uniform(0.5, 1.0),
                "is_fraud": True,
            })

    return data


def main():
    print("Generating synthetic training data...")
    data = generate_synthetic_data(10000)

    print("Training Isolation Forest model...")
    engine = FraudEngine()
    engine.train_model(data)

    print("Model trained and saved to fraud/models/")
    print(f"  - Normal transactions: {sum(1 for d in data if not d['is_fraud'])}")
    print(f"  - Fraudulent transactions: {sum(1 for d in data if d['is_fraud'])}")


if __name__ == "__main__":
    main()
