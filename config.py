#!/usr/bin/env python3
"""SecurePay - Configuration centrale (lab + cloud-ready)."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Paramètres de l'application SecurePay."""

    APP_NAME: str = "SecurePay"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "lab"
    DEBUG: bool = False

    DATABASE_URL: str = "postgresql+asyncpg://securepay:securepay_dev@localhost:5433/securepay"
    REDIS_URL: str = "redis://localhost:6380/0"
    RABBITMQ_URL: str = "amqp://securepay:securepay_dev@localhost:5672/"

    KEYCLOAK_URL: str = "http://localhost:8081"
    KEYCLOAK_REALM: str = "securepay"
    KEYCLOAK_CLIENT_ID: str = "securepay-gateway"
    KEYCLOAK_CLIENT_SECRET: str = ""

    JWT_SECRET_KEY: str = "dev-secret-change-in-production"
    JWT_ALGORITHM: str = "RS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # AES-256-GCM 32-byte key hex (64 chars). Lab default is deterministic — rotate in prod/Vault.
    VAULT_MASTER_KEY: str = ""
    FERNET_KEY: str = ""  # legacy, unused

    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:9000,http://127.0.0.1:9000"

    @property
    def origin_list(self) -> list[str]:
        return [part.strip() for part in self.ALLOWED_ORIGINS.split(",") if part.strip()]
    RATE_LIMIT_PER_MINUTE: int = 60
    PAYMENT_RATE_LIMIT_PER_MINUTE: int = 10

    FRAUD_THRESHOLD: float = 0.85
    FRAUD_REVIEW_THRESHOLD: float = 0.45
    FRAUD_MODEL_PATH: str = "./fraud/models/"

    PAYMENT_SERVICE_URL: str = "http://localhost:8001"
    TOKENIZATION_SERVICE_URL: str = "http://localhost:8002"
    FRAUD_SERVICE_URL: str = "http://localhost:8003"
    LEGACY_CORE_URL: str = ""

    THREEDS_SERVER_URL: str = "http://localhost:8020"
    DIRECTORY_SERVER_URL: str = "http://localhost:8021"
    ACS_SERVER_URL: str = "http://localhost:8022"

    WEBHOOK_SECRET: str = "lab-webhook-secret-change-me"
    WEBHOOK_MAX_AGE_SECONDS: int = 300

    SECUREPAY_EVENT_LOG: str = "logs/securepay-events.jsonl"

    # --- Phase 2 : stack bancaire ---
    KAFKA_BOOTSTRAP_SERVERS: str = ""          # vide = pas de Kafka (JSONL uniquement)
    KAFKA_EVENTS_TOPIC: str = "securepay.events"
    KAFKA_SECURITY_PROTOCOL: str = "PLAINTEXT" # PLAINTEXT | SSL | SASL_SSL

    USE_GRPC: bool = False                      # True = appels internes via gRPC
    GRPC_PAYMENT_TARGET: str = "localhost:50051"
    GRPC_FRAUD_TARGET: str = "localhost:50052"

    VAULT_URL: str = "http://localhost:8200"
    VAULT_TOKEN: str = ""                       # lab: VAULT_DEV_ROOT_TOKEN
    VAULT_DB_MOUNT: str = "database"
    VAULT_DB_ROLE: str = "securepay-db-ro"
    VAULT_PKI_MOUNT: str = "pki"
    VAULT_PKI_ROLE: str = "securepay-service"

    NETWORK_TOKEN_VAULT_PATH: str = "secret/securepay/network-token"   # HSM/master sim
    SESSION_VAULT_HOST: str = "localhost"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
