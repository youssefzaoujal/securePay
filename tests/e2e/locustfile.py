"""Locust load tests - SecurePay API."""

from locust import HttpUser, task, between
import random
import uuid


class MerchantUser(HttpUser):
    """Simuler un marchand utilisant l'API SecurePay."""

    wait_time = between(1, 3)

    def on_start(self):
        """Authentification au démarrage de la session."""
        # Obtenir un token via client_credentials
        response = self.client.post(
            "http://localhost:8080/realms/securepay/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "merchant-api",
                "client_secret": "CHANGE_ME_IN_PRODUCTION",
            },
        )
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.headers = {}

    @task(5)
    def health_check(self):
        self.client.get("/health")

    @task(3)
    def create_payment(self):
        """Créer un paiement (scénario principal)."""
        amount = round(random.uniform(5, 5000), 2)
        self.client.post(
            "/api/v1/payments",
            json={
                "amount": amount,
                "currency": "EUR",
                "card_number": f"411111111111{random.randint(1000, 9999)}",
                "card_expiry": "12/25",
                "card_cvv": str(random.randint(100, 999)),
                "merchant_id": "MERCH_001",
                "description": f"Load test payment #{uuid.uuid4().hex[:8]}",
            },
            headers=self.headers,
            name="/api/v1/payments [POST]",
        )

    @task(2)
    def tokenize_card(self):
        """Tokeniser une carte."""
        self.client.post(
            "/api/v1/tokens",
            json={
                "card_number": f"411111111111{random.randint(1000, 9999)}",
                "card_expiry": "12/25",
                "card_cvv": str(random.randint(100, 999)),
            },
            headers=self.headers,
            name="/api/v1/tokens [POST]",
        )

    @task(2)
    def check_fraud(self):
        """Vérifier la fraude."""
        self.client.post(
            "/api/v1/fraud/check",
            json={
                "amount": round(random.uniform(10, 10000), 2),
                "currency": "EUR",
                "card_token": f"tok_{uuid.uuid4().hex[:16]}",
                "merchant_id": "MERCH_001",
                "ip_address": "192.168.1.1",
            },
            headers=self.headers,
            name="/api/v1/fraud/check [POST]",
        )

    @task(1)
    def get_current_user(self):
        """Récupérer les infos de l'utilisateur courant."""
        self.client.get(
            "/api/v1/me",
            headers=self.headers,
            name="/api/v1/me [GET]",
        )
