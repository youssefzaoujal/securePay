"""Mesure du moteur de fraude — vocabulaire type Adyen Protect.

Produit des chiffres réels et défendables :
  - détection rate  (Recall)  : % de fraude simulée bloquée ou en review
  - false positive rate (FPR) : % de trafic bénin faussement flagged
  - precision, F1

Format de sortie == reporting public des PSP (Adyen Protect GRC) :
    "+16% de fraude détectée / -33% de faux positifs" se raconte en entretien.

Usage :
    python -m scripts.benchmark_fraud_engine
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timezone

from fraud.engine import FraudEngine


def _clamp(score: float) -> float:
    return round(max(0.0, min(1.0, score)), 4)


def generate_dataset(seed: int = 42, size: int = 2000) -> list[dict]:
    rng = random.Random(seed)
    rows: list[dict] = []
    novel_counter = 100000

    for i in range(size):
        is_fraud = rng.random() < 0.08  # 8% de fraude simulée
        base_amount = rng.uniform(10.0, 5000.0)

        # Fraude "novelle" : token jamais vu, montant banal, IP bénigne.
        # — vol de carte rétif/one-shot ; un moteur de vélocité ne le voit pas.
        if is_fraud and rng.random() < 0.35:
            amount = rng.uniform(50.0, 1200.0)
            card_token = f"tok_novel_{novel_counter:06d}"
            novel_counter += 1
            ip = f"10.7.{rng.randint(0, 254)}.{rng.randint(1, 254)}"
            merchant = "merchant-api"
        else:
            amount = base_amount * (rng.uniform(1.5, 4.0) if is_fraud else 1.0)
            if is_fraud and rng.random() < 0.6:
                amount = rng.uniform(6000.0, 30000.0)  # montants élevés = indicateur

            if not is_fraud and rng.random() < 0.95:
                ip = f"10.0.{rng.randint(0, 254)}.{rng.randint(1, 254)}"
            elif rng.random() < 0.60:  # ~3% de bénin sur plage à risque (nuit/Tor)
                ip = "10.255.7.9"  # plage lab "Tor/high-risk"
            else:
                ip = ""  # ~2% : paiement sans IP (token présenté côté serveur)

            card_token = (
                f"tok_{i:06d}"
                if not is_fraud or rng.random() < 0.3
                else f"tok_fraud_{rng.randint(0, 50):04d}"
            )
            merchant = "MERCH_HIGH_RISK" if is_fraud and rng.random() < 0.3 else "merchant-api"

        rows.append(
            {
                "amount": round(amount, 2),
                "currency": "EUR",
                "card_token": card_token,
                "merchant_id": merchant,
                "ip_address": ip,
                "is_fraud": is_fraud,
            }
        )
    return rows


def run_benchmark(seed: int = 42, size: int = 2000) -> dict:
    # Horloge virtuelle : un rejeu séquentiel avance de 0.3s par tx -> 2000 tx
    # s'étalent sur ~10 min. Les fenêtres de vélocité (60s) se comportent alors
    # comme en production, au lieu de tout compresser sur <60s de temps réel.
    import itertools

    clock_iter = iter(itertools.count())
    fake_time = lambda: clock_iter.__next__() * 0.3  # noqa: E731

    engine = FraudEngine(clock=fake_time)
    rows = generate_dataset(seed=seed, size=size)

    tp = fp = tn = fn = 0
    hard_fp = 0
    reviewed_benign = 0
    blocked_or_review = 0
    for row in rows:
        result = engine.analyze(
            amount=row["amount"],
            currency=row["currency"],
            card_token=row["card_token"],
            merchant_id=row["merchant_id"],
            ip_address=row["ip_address"],
        )
        decision = result["recommendation"]
        flagged = decision in ("review", "decline")
        hard_block = decision == "decline"

        if flagged and row["is_fraud"]:
            tp += 1
            blocked_or_review += 1
        elif flagged and not row["is_fraud"]:
            fp += 1
            if hard_block:
                hard_fp += 1  # vrai faux positif : bénin refusé sans chance de SCA
            else:
                reviewed_benign += 1  # friction SCA sur trafic bénin (résolvable)
        elif not flagged and row["is_fraud"]:
            fn += 1
        else:
            tn += 1

    total_fraud = tp + fn
    total_benign = fp + tn
    detection_rate = tp / total_fraud if total_fraud else 0.0
    false_positive_rate = fp / total_benign if total_benign else 0.0
    hard_block_fpr = hard_fp / total_benign if total_benign else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * detection_rate / (precision + detection_rate) if (precision + detection_rate) else 0.0

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {"total": size, "fraud": total_fraud, "benign": total_benign},
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "detection_rate": round(detection_rate, 4),
            "false_positive_rate": round(false_positive_rate, 5),
            "hard_block_fpr": round(hard_block_fpr, 5),
            "review_friction_rate": round(reviewed_benign / total_benign if total_benign else 0.0, 5),
            "precision": round(precision, 4),
            "f1": round(f1, 4),
            "blocked_or_review": blocked_or_review,
        },
        "report_format": "Adyen Protect-style: recall (fraud caught) & FPR (benign) split hard-block vs SCA-friction",
    }


def main() -> int:
    report = run_benchmark()
    m = report["metrics"]
    d = report["dataset"]
    print(
        f"[fraud-benchmark] dataset={d['total']} (fraud={d['fraud']}, benign={d['benign']})\n"
        f"  detection_rate (recall) = {m['detection_rate']:.1%}\n"
        f"  total false_positive_rate = {m['false_positive_rate']:.3%}\n"
        f"    - hard-block FPR          = {m['hard_block_fpr']:.3%}  (bénin refusé sans SCA)\n"
        f"    - review/SCA friction     = {m['review_friction_rate']:.3%}  (résolu par challenge)\n"
        f"  precision               = {m['precision']:.1%}\n"
        f"  f1                      = {m['f1']:.1%}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())