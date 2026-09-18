"""Tests d'intégration - Base de données."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from models import Base, Transaction, VaultEntry, AuditLog


DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    session_factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session


class TestTransactionModel:
    @pytest.mark.asyncio
    async def test_create_transaction(self, db_session):
        tx = Transaction(
            merchant_id="MERCH_001",
            amount=99.99,
            currency="EUR",
            card_token="tok_test123",
            card_last_four="1111",
            card_brand="visa",
        )
        db_session.add(tx)
        await db_session.commit()

        assert tx.id is not None
        assert tx.status.value == "pending"

    @pytest.mark.asyncio
    async def test_transaction_index_on_merchant(self, db_session):
        for i in range(5):
            tx = Transaction(
                merchant_id="MERCH_001",
                amount=float(i),
                card_token=f"tok_{i}",
                card_last_four="1111",
                card_brand="visa",
            )
            db_session.add(tx)
        await db_session.commit()

        result = await db_session.execute(
            Transaction.__table__.select().where(
                Transaction.merchant_id == "MERCH_001"
            )
        )
        assert len(result.all()) == 5


class TestVaultEntryModel:
    @pytest.mark.asyncio
    async def test_create_vault_entry(self, db_session):
        entry = VaultEntry(
            token="tok_abc123",
            encrypted_pan=b"encrypted_data",
            encrypted_expiry=b"encrypted_expiry",
            card_last_four="1111",
            card_brand="visa",
        )
        db_session.add(entry)
        await db_session.commit()

        assert entry.id is not None
        assert entry.is_active is True


class TestAuditLogModel:
    @pytest.mark.asyncio
    async def test_create_audit_log(self, db_session):
        log = AuditLog(
            event_type="payment.created",
            user_id="user_001",
            merchant_id="MERCH_001",
            action="create",
            result="success",
            ip_address="192.168.1.1",
        )
        db_session.add(log)
        await db_session.commit()

        assert log.id is not None
