"""Database models - SQLAlchemy ORM pour SecurePay."""

from datetime import datetime, timezone
from enum import Enum as PyEnum
import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class PaymentStatus(str, PyEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"
    FRAUD_REVIEW = "fraud_review"
    CHALLENGE_REQUIRED = "challenge_required"


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    merchant_id = Column(String(64), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(3), nullable=False, default="EUR")
    status = Column(
        Enum(PaymentStatus, name="payment_status"),
        nullable=False,
        default=PaymentStatus.PENDING,
    )
    card_token = Column(String(64), nullable=False)
    card_last_four = Column(String(4), nullable=False)
    card_brand = Column(String(20), nullable=False)
    authorization_code = Column(String(32), nullable=True)
    description = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    fraud_score = Column(Float, nullable=True)
    fraud_flags = Column(JSON, nullable=True)
    correlation_id = Column(String(32), nullable=True, index=True)
    three_ds_status = Column(String(32), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_transactions_created_at", "created_at"),
        Index("ix_transactions_status", "status"),
        Index("ix_transactions_merchant_created", "merchant_id", "created_at"),
    )


class VaultEntry(Base):
    """Coffre PAN — AES-256-GCM. CVV JAMAIS stocké (PCI-DSS Req 3.2)."""

    __tablename__ = "vault_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(String(64), unique=True, nullable=False, index=True)
    encrypted_pan = Column(LargeBinary, nullable=False)
    encrypted_expiry = Column(LargeBinary, nullable=False)
    card_last_four = Column(String(4), nullable=False)
    card_brand = Column(String(20), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=True)


class Merchant(Base):
    __tablename__ = "merchants"

    id = Column(String(64), primary_key=True)
    legal_name = Column(String(255), nullable=False)
    webhook_url = Column(String(512), nullable=True)
    status = Column(String(16), nullable=False, default="active")
    mcc = Column(String(4), nullable=True)
    oauth_client_id = Column(String(128), nullable=True, unique=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (UniqueConstraint("oauth_client_id", name="uq_merchant_oauth_client"),)


class AuditLog(Base):
    """Journal d'audit PCI-DSS Req 10."""

    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    merchant_id = Column(String(64), nullable=True)
    resource_type = Column(String(32), nullable=True)
    resource_id = Column(String(64), nullable=True)
    action = Column(String(32), nullable=False)
    result = Column(String(16), nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )


class DetectionAlert(Base):
    __tablename__ = "detection_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(String(128), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(16), nullable=False)
    mitre_technique = Column(String(32), nullable=True)
    source_ip = Column(String(45), nullable=True)
    merchant_id = Column(String(64), nullable=True)
    event_count = Column(Integer, nullable=False, default=1)
    status = Column(String(16), nullable=False, default="open")
    details = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
