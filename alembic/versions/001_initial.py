"""Initial schema - Tables de base SecurePay.

Revision ID: 001_initial
Revises:
Create Date: 2026-08-26
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enum payment_status
    payment_status = sa.Enum(
        "pending", "succeeded", "failed", "refunded", "fraud_review",
        name="payment_status",
    )
    payment_status.create(op.get_bind(), checkfirst=True)

    # Transactions
    op.create_table(
        "transactions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("merchant_id", sa.String(64), nullable=False),
        sa.Column("amount", sa.Float(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="EUR"),
        sa.Column("status", payment_status, nullable=False, server_default="pending"),
        sa.Column("card_token", sa.String(64), nullable=False),
        sa.Column("card_last_four", sa.String(4), nullable=False),
        sa.Column("card_brand", sa.String(20), nullable=False),
        sa.Column("authorization_code", sa.String(32), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("fraud_score", sa.Float(), nullable=True),
        sa.Column("fraud_flags", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_transactions_created_at", "transactions", ["created_at"])
    op.create_index("ix_transactions_status", "transactions", ["status"])
    op.create_index("ix_transactions_merchant_created", "transactions", ["merchant_id", "created_at"])

    # Vault entries (données cartes chiffrées)
    op.create_table(
        "vault_entries",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("token", sa.String(64), unique=True, nullable=False),
        sa.Column("encrypted_pan", sa.LargeBinary, nullable=False),
        sa.Column("encrypted_expiry", sa.LargeBinary, nullable=False),
        sa.Column("encrypted_cvv", sa.LargeBinary, nullable=False),
        sa.Column("card_last_four", sa.String(4), nullable=False),
        sa.Column("card_brand", sa.String(20), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_vault_entries_token", "vault_entries", ["token"], unique=True)

    # Audit logs (PCI-DSS Req 10)
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=True),
        sa.Column("merchant_id", sa.String(64), nullable=True),
        sa.Column("resource_type", sa.String(32), nullable=True),
        sa.Column("resource_id", sa.String(64), nullable=True),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("vault_entries")
    op.drop_table("transactions")
    sa.Enum(name="payment_status").drop(op.get_bind(), checkfirst=True)
