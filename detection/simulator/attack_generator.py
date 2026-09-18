"""
SecurePay Attack Simulator
Simule des attaques réalistes contre l'API SecurePay pour alimenter le SOC.

Scénarios:
  1. Card Testing (carding) - Multi-cartes, même IP
  2. Credential Stuffing - Tentatives de login en rafale
  3. BOLA - Accès cross-merchant
  4. Fraud Spike - Montants anormaux

Usage:
  python -m detection.simulator.attack_generator --scenario carding --target http://localhost:8000
"""

import asyncio
import httpx
import json
import random
import string
import uuid
import argparse
import time
from datetime import datetime, timezone
from pathlib import Path


class AttackSimulator:
    """Simulateur d'attaques pour alimenter les logs de détection."""

    def __init__(self, target_url: str, log_dir: str = "./detection/simulator/logs"):
        self.target = target_url.rstrip("/")
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.client = httpx.AsyncClient(timeout=10.0, follow_redirects=False)

    async def close(self):
        await self.client.aclose()

    def _log_event(self, event: dict):
        """Écrire un événement au format JSON pour Wazuh/ELK."""
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        event["source"] = "securepay-attack-simulator"

        log_file = self.log_dir / f"events_{datetime.now().strftime('%Y%m%d')}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(event) + "\n")

    def _random_card(self) -> str:
        """Générer un numéro de carte aléatoire (test)."""
        prefix = random.choice(["4", "5", "34", "37", "6011"])
        remaining = "".join(random.choices(string.digits, k=16 - len(prefix)))
        return prefix + remaining

    def _random_ip(self) -> str:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    # ─── Scenario 1: Card Testing ───────────────────────────────
    async def simulate_carding(self, num_attempts: int = 50, attacker_ip: str | None = None):
        """
        Simule un carding: beaucoup de tentatives de paiement avec
        différentes cartes depuis la même IP.
        """
        print(f"[CARDING] Démarrage: {num_attempts} tentatives depuis IP {attacker_ip or 'aléatoire'}")
        ip = attacker_ip or self._random_ip()
        failed_count = 0
        success_count = 0

        for i in range(num_attempts):
            card = self._random_card()
            amount = round(random.uniform(5, 5000), 2)
            expiry = f"{random.randint(1,12):02d}/{random.randint(25,30)}"

            payload = {
                "amount": amount,
                "currency": "EUR",
                "card_number": card,
                "card_expiry": expiry,
                "card_cvv": str(random.randint(100, 999)),
                "merchant_id": "MERCH_001",
                "description": f"Carding test #{i+1}",
            }

            try:
                resp = await self.client.post(
                    f"{self.target}/api/v1/payments",
                    json=payload,
                    headers={"X-Forwarded-For": ip, "Content-Type": "application/json"},
                )
                status = "success" if resp.status_code < 400 else "failed"
                if status == "failed":
                    failed_count += 1
                else:
                    success_count += 1
            except Exception as e:
                status = "error"
                failed_count += 1

            self._log_event({
                "event_type": "payment_attempt",
                "scenario": "card_testing",
                "source_ip": ip,
                "card_token": f"tok_{uuid.uuid4().hex[:16]}",
                "amount": amount,
                "currency": "EUR",
                "merchant_id": "MERCH_001",
                "status": status,
                "http_status": resp.status_code if 'resp' in dir() else None,
                "attempt_number": i + 1,
            })

            # Pause réaliste entre tentatives
            await asyncio.sleep(random.uniform(0.1, 0.5))

            # Log de progression
            if (i + 1) % 10 == 0:
                print(f"  [{i+1}/{num_attempts}] failed={failed_count} success={success_count}")

        self._log_event({
            "event_type": "carding_summary",
            "scenario": "card_testing",
            "source_ip": ip,
            "total_attempts": num_attempts,
            "failed_count": failed_count,
            "success_count": success_count,
            "detection_signal": "high_volume_failed_payments",
        })

        print(f"[CARDING] Terminé: {failed_count} échecs, {success_count} succès")
        return {"failed": failed_count, "success": success_count}

    # ─── Scenario 2: Credential Stuffing ────────────────────────
    async def simulate_credential_stuffing(self, num_attempts: int = 30, attacker_ip: str | None = None):
        """
        Simule un credential stuffing: tentatives de login avec
        différents usernames depuis la même IP.
        """
        print(f"[CREDENTIAL STUFFING] Démarrage: {num_attempts} tentatives")
        ip = attacker_ip or self._random_ip()

        # Liste de usernames courants à tester
        usernames = [
            "admin", "merchant1", "merchant2", "test", "user",
            "administrator", "root", "support", "info", "api",
            "merchant_test", "dev", "staging", "prod",
        ]

        for i in range(num_attempts):
            username = random.choice(usernames) + (str(random.randint(1, 99)) if random.random() > 0.5 else "")
            password = "".join(random.choices(string.ascii_letters + string.digits, k=12))

            try:
                resp = await self.client.post(
                    f"{self.target}/auth/login",
                    json={"username": username, "password": password},
                    headers={"X-Forwarded-For": ip, "Content-Type": "application/json"},
                )
                status = "success" if resp.status_code == 200 else "failed"
            except Exception:
                status = "error"

            self._log_event({
                "event_type": "authentication_attempt",
                "scenario": "credential_stuffing",
                "source_ip": ip,
                "username": username,
                "status": status,
                "attempt_number": i + 1,
            })

            await asyncio.sleep(random.uniform(0.05, 0.3))

            if (i + 1) % 10 == 0:
                print(f"  [{i+1}/{num_attempts}] tentatives effectuées")

        self._log_event({
            "event_type": "credential_stuffing_summary",
            "scenario": "credential_stuffing",
            "source_ip": ip,
            "total_attempts": num_attempts,
            "unique_usernames": len(set(usernames)),
            "detection_signal": "rapid_auth_failures",
        })

        print(f"[CREDENTIAL STUFFING] Terminé: {num_attempts} tentatives depuis {ip}")

    # ─── Scenario 3: BOLA ──────────────────────────────────────
    async def simulate_bola(self, num_attempts: int = 20, attacker_ip: str | None = None):
        """
        Simule un BOLA: un merchant tente d'accéder aux ressources
        d'un autre merchant.
        """
        print(f"[BOLA] Démarrage: {num_attempts} tentatives cross-merchant")
        ip = attacker_ip or self._random_ip()

        for i in range(num_attempts):
            target_merchant = f"MERCH_{random.randint(100, 999):03d}"
            resource_id = f"pay_{uuid.uuid4().hex[:16]}"

            try:
                resp = await self.client.get(
                    f"{self.target}/api/v1/merchants/{target_merchant}/transactions/{resource_id}",
                    headers={
                        "X-Forwarded-For": ip,
                        "Authorization": "Bearer fake_token_for_merchant_001",
                    },
                )
                status_code = resp.status_code
            except Exception:
                status_code = 0

            self._log_event({
                "event_type": "authorization_error",
                "scenario": "bola",
                "source_ip": ip,
                "merchant_id": "MERCH_001",
                "target_merchant_id": target_merchant,
                "resource_type": "transaction",
                "resource_id": resource_id,
                "http_method": "GET",
                "http_path": f"/api/v1/merchants/{target_merchant}/transactions/{resource_id}",
                "status_code": status_code,
                "error_type": "object_level_authorization" if status_code == 403 else "other",
            })

            await asyncio.sleep(random.uniform(0.2, 1.0))

        self._log_event({
            "event_type": "bola_summary",
            "scenario": "bola",
            "source_ip": ip,
            "total_attempts": num_attempts,
            "detection_signal": "cross_merchant_access_denied",
        })

        print(f"[BOLA] Terminé: {num_attempts} tentatives depuis {ip}")

    # ─── Scenario 4: Fraud Spike ───────────────────────────────
    async def simulate_fraud_spike(self, num_attempts: int = 15, attacker_ip: str | None = None):
        """
        Simule un spike de fraude: transactions à très haut montant
        avec scores de fraude élevés.
        """
        print(f"[FRAUD SPIKE] Démarrage: {num_attempts} transactions à haut risque")
        ip = attacker_ip or self._random_ip()

        for i in range(num_attempts):
            amount = round(random.uniform(5000, 50000), 2)

            self._log_event({
                "event_type": "fraud_score",
                "scenario": "fraud_spike",
                "transaction_id": f"pay_{uuid.uuid4().hex[:16]}",
                "source_ip": ip,
                "merchant_id": random.choice(["MERCH_001", "MERCH_002"]),
                "risk_score": round(random.uniform(0.85, 0.99), 4),
                "risk_level": random.choice(["high", "critical"]),
                "flags": random.sample([
                    "Montant très élevé",
                    "IP non disponible",
                    "ML anomaly score élevé",
                    "Vélocité inhabituelle",
                ], k=random.randint(1, 3)),
                "amount": amount,
                "currency": "EUR",
                "card_token": f"tok_{uuid.uuid4().hex[:16]}",
            })

            await asyncio.sleep(random.uniform(0.5, 2.0))

        self._log_event({
            "event_type": "fraud_spike_summary",
            "scenario": "fraud_spike",
            "source_ip": ip,
            "total_transactions": num_attempts,
            "detection_signal": "high_fraud_score_cluster",
        })

        print(f"[FRAUD SPIKE] Terminé: {num_attempts} transactions à haut risque")


async def main():
    parser = argparse.ArgumentParser(description="SecurePay Attack Simulator")
    parser.add_argument("--scenario", choices=["carding", "credential_stuffing", "bola", "fraud_spike", "all"], default="all")
    parser.add_argument("--target", default="http://localhost:8000")
    parser.add_argument("--attempts", type=int, default=20)
    parser.add_argument("--attacker-ip", default=None)
    args = parser.parse_args()

    sim = AttackSimulator(args.target)

    try:
        scenarios = {
            "carding": sim.simulate_carding,
            "credential_stuffing": sim.simulate_credential_stuffing,
            "bola": sim.simulate_bola,
            "fraud_spike": sim.simulate_fraud_spike,
        }

        if args.scenario == "all":
            for name, func in scenarios.items():
                print(f"\n{'='*60}")
                print(f"  SCÉNARIO: {name.upper()}")
                print(f"{'='*60}")
                await func(num_attempts=args.attempts, attacker_ip=args.attacker_ip)
                await asyncio.sleep(2)
        else:
            await scenarios[args.scenario](num_attempts=args.attempts, attacker_ip=args.attacker_ip)
    finally:
        await sim.close()

    print(f"\nLogs écrits dans: {sim.log_dir}")


if __name__ == "__main__":
    asyncio.run(main())
