"""Tests ISO 20022 (Phase 3) — round-trip pacs.008/002, camt.053, IBAN checksum."""

from __future__ import annotations

import pytest

from iso20022.messages import (
    AccountStatement,
    CreditTransfer,
    PaymentStatusReport,
    validate_iban,
)


def test_validate_iban_known_good():
    assert validate_iban("FR7630006000011234567890189") is True
    assert validate_iban("DE75512108001245126199") is True
    assert validate_iban("GB29NWBK60161331926819") is True


def test_validate_iban_bad():
    assert validate_iban("FR7630006000011234567890180") is False
    assert validate_iban("not-an-iban") is False


def test_pacs008_round_trip():
    ct = CreditTransfer(
        message_id="MSG-001",
        creation_dt="2026-09-04T10:00:00.000",
        id="E2E-42",
        amount=153.75,
        debtor_name="SA SecurePay",
        debtor_iban="DE75512108001245126199",
        debtor_bic="COBADEFFXXX",
        creditor_name="Fournisseur SARL",
        creditor_iban="FR7630006000011234567890189",
        creditor_bic="AGRIFRPP",
        remittance="Facture 2026-09",
    )
    xml = ct.build()
    assert "pacs.008.001.08" in xml
    assert "MSG-001" in xml
    assert "153.75" in xml
    parsed = CreditTransfer.load(CreditTransfer(), xml)
    assert parsed["message_id"] == "MSG-001"
    assert parsed["amount"] == 153.75
    assert parsed["currency"] == "EUR"
    assert parsed["creditor_iban"] == "FR7630006000011234567890189"


def test_pacs008_currency_attr():
    ct = CreditTransfer("M", "2026-09-04", "T", 99.99, currency="USD",
                        debtor_iban="DE75512108001245126199", creditor_iban="FR7630006000011234567890189")
    parsed = CreditTransfer.load(CreditTransfer(), ct.build())
    assert parsed["currency"] == "USD"


def test_pacs002_round_trip_and_statuses():
    for status in ("ACCP", "ACSP", "ACTC"):
        pr = PaymentStatusReport(message_id="MSG-S", original_message_id="MSG-001", status=status)
        parsed = PaymentStatusReport.load(PaymentStatusReport(), pr.build())
        assert parsed["status"] == status


def test_pacs002_reason_code_included():
    pr = PaymentStatusReport("S", "O", "ACTC", reason="AC04")
    assert "AC04" in pr.build()


def test_camt053_round_trip_with_entries():
    stmt = AccountStatement(
        message_id="ST-1",
        account_iban="FR7630006000011234567890189",
        statement_id="STMT-9",
        entries=[
            {"amount": 153.75, "currency": "EUR", "credit_debit": "CRDT", "reference": "ref-1"},
            {"amount": 12.00, "currency": "EUR", "credit_debit": "DBIT", "reference": "ref-2"},
        ],
    )
    xml = stmt.build()
    parsed = AccountStatement.load(AccountStatement(), xml)
    assert parsed["message_id"] == "ST-1"
    assert parsed["account_iban"] == "FR7630006000011234567890189"
    assert len(parsed["entries"]) == 2
    assert parsed["entries"][0]["credit_debit"] == "CRDT"
    assert parsed["entries"][1]["amount"] == 12.0