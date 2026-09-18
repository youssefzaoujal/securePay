"""Drop encrypted_cvv — PCI-DSS Req 3.2.2 SAD never stored.

Revision ID: 002_no_cvv
Revises: 001_initial
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002_no_cvv"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("vault_entries", "encrypted_cvv")
    op.add_column("transactions", sa.Column("correlation_id", sa.String(32), nullable=True))
    op.add_column("transactions", sa.Column("three_ds_status", sa.String(32), nullable=True))
    op.create_index("ix_transactions_correlation_id", "transactions", ["correlation_id"])


def downgrade() -> None:
    op.drop_index("ix_transactions_correlation_id", table_name="transactions")
    op.drop_column("transactions", "three_ds_status")
    op.drop_column("transactions", "correlation_id")
    op.add_column("vault_entries", sa.Column("encrypted_cvv", sa.LargeBinary(), nullable=True))
