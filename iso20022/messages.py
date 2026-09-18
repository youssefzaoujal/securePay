"""ISO 20022 — messages de paiement XML (pacs.008, pacs.002, camt.053).

Leat-build sur ElementTree avec les namespace réels ISO. Le but : savoir
construire ET relire un message conforme — le standard SWIFT/SEPA moderne —
avec validation des champs structurants (IBAN, BIC, montant, devise).

Un "pacs.008" bien formé est la preuve que la vision architecturale couvre le
virement/SEPA, pas seulement le paiement carte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from xml.etree import ElementTree as ET

NS_PACS008 = "urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08"
NS_PACS002 = "urn:iso:std:iso:20022:tech:xsd:pacs.002.001.10"
NS_CAMT053 = "urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"
NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"

_STATUS_VALID = ("ACCP", "ACSP", "ACTC")  # PACS.002 Accepted/InProgress statuses


class ISO20022Error(ValueError):
    pass


def _el(tag: str, ns: str, text: str | None = None) -> ET.Element:
    el = ET.Element(f"{{{ns}}}{tag}")
    if text is not None:
        el.text = str(text)
    return el


def _q(tag: str, ns: str) -> str:
    return f"{{{ns}}}{tag}"


def _find(el: ET.Element, ns: str, path: str) -> Optional[ET.Element]:
    cur = el
    for part in path.split("/"):
        kw = {"tag": _q(part, ns)}
        found = cur.find(part, namespaces={"": ns}) if False else _find_step(cur, ns, part)
        if found is None:
            return None
        cur = found
    return cur


def _find_step(el: ET.Element, ns: str, part: str) -> Optional[ET.Element]:
    for child in el:
        if child.tag == _q(part, ns):
            return child
    return None


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


@dataclass
class CreditTransfer:
    message_id: str = ""
    creation_dt: str = ""
    id: str = ""
    amount: float = 0.0
    currency: str = "EUR"
    debtor_name: str = ""
    debtor_iban: str = ""
    debtor_bic: str = ""
    creditor_name: str = ""
    creditor_iban: str = ""
    creditor_bic: str = ""
    remittance: str = ""

    def build(self) -> str:
        root = ET.Element(_q("Document", NS_PACS008), {
            f"{{{NS_XSI}}}schemaLocation": f"{NS_PACS008} pacs.008.001.08.xsd",
        })
        cstmr = _el("CstmrCdtTrfInitn", NS_PACS008)
        root.append(cstmr)
        grp = _el("GrpHdr", NS_PACS008)
        grp.append(_el("MsgId", NS_PACS008, self.message_id))
        grp.append(_el("CreDtTm", NS_PACS008, self.creation_dt))
        grp.append(_el("NbOfTxs", NS_PACS008, "1"))
        grp.append(_el("InitgPty", NS_PACS008))
        cstmr.append(grp)

        pmt = _el("PmtInf", NS_PACS008)
        pmt.append(_el("PmtInfId", NS_PACS008, self.id))
        pmt.append(_el("PmtMtd", NS_PACS008, "TRF"))
        pmt.append(_el("BtchBookg", NS_PACS008, "false"))
        pmt.append(_el("ReqdExctnDt", NS_PACS008, self.creation_dt[:10]))
        dbtr = _el("Dbtr", NS_PACS008)
        dbtr.append(_el("Nm", NS_PACS008, self.debtor_name))
        pmt.append(dbtr)
        dbtr_acct = _el("DbtrAcct", NS_PACS008)
        dbtr_acct.append(_el("Id", NS_PACS008))
        dbtr_acct.find(_q("Id", NS_PACS008)).append(_el("IBAN", NS_PACS008, self.debtor_iban))
        pmt.append(dbtr_acct)
        dbtr_agt = _el("DbtrAgt", NS_PACS008)
        dbtr_agt.append(_el("FinInstnId", NS_PACS008))
        dbtr_agt.find(_q("FinInstnId", NS_PACS008)).append(_el("BICFI", NS_PACS008, self.debtor_bic))
        pmt.append(dbtr_agt)

        cdt_trx = _el("CdtTrfTxInf", NS_PACS008)
        cdt_trx.append(_el("PmtId", NS_PACS008))
        cdt_trx.find(_q("PmtId", NS_PACS008)).append(_el("EndToEndId", NS_PACS008, self.id))
        amt = _el("Amt", NS_PACS008)
        amt.append(_el("InstdAmt", NS_PACS008, f"{self.amount:.2f}"))
        amt.find(_q("InstdAmt", NS_PACS008)).set("Ccy", self.currency)
        cdt_trx.append(amt)
        cdtr = _el("Cdtr", NS_PACS008)
        cdtr.append(_el("Nm", NS_PACS008, self.creditor_name))
        cdt_trx.append(cdtr)
        cdtr_acct = _el("CdtrAcct", NS_PACS008)
        cdtr_acct.append(_el("Id", NS_PACS008))
        cdtr_acct.find(_q("Id", NS_PACS008)).append(_el("IBAN", NS_PACS008, self.creditor_iban))
        cdt_trx.append(cdtr_acct)
        cdtr_agt = _el("CdtrAgt", NS_PACS008)
        cdtr_agt.append(_el("FinInstnId", NS_PACS008))
        cdtr_agt.find(_q("FinInstnId", NS_PACS008)).append(_el("BICFI", NS_PACS008, self.creditor_bic))
        cdt_trx.append(cdtr_agt)
        if self.remittance:
            rmt = _el("RmtInf", NS_PACS008)
            rmt.append(_el("Ustrd", NS_PACS008, self.remittance))
            cdt_trx.append(rmt)
        pmt.append(cdt_trx)
        cstmr.append(pmt)

        ET.register_namespace("", NS_PACS008)
        return ET.tostring(root, encoding="unicode", xml_declaration=False)

    def load(self, xml: str) -> dict:
        root = ET.fromstring(xml)
        if root.tag != _q("Document", NS_PACS008):
            raise ISO20022Error("ce n'est pas un pacs.008")
        grp = _find_step(root, NS_PACS008, "CstmrCdtTrfInitn").find(_q("GrpHdr", NS_PACS008))
        pmt = _find_step(root, NS_PACS008, "CstmrCdtTrfInitn").find(_q("PmtInf", NS_PACS008))
        tx = pmt.find(_q("CdtTrfTxInf", NS_PACS008))
        amount_el = tx.find(_q("Amt", NS_PACS008)).find(_q("InstdAmt", NS_PACS008))
        return {
            "message_id": _text(grp.find(_q("MsgId", NS_PACS008))),
            "creation_dt": _text(grp.find(_q("CreDtTm", NS_PACS008))),
            "id": _text(tx.find(_q("PmtId", NS_PACS008)).find(_q("EndToEndId", NS_PACS008))),
            "amount": float(amount_el.text),
            "currency": amount_el.get("Ccy") or "EUR",
            "creditor_iban": _text(tx.find(_q("CdtrAcct", NS_PACS008)).find(_q("Id", NS_PACS008)).find(_q("IBAN", NS_PACS008))),
        }


@dataclass
class PaymentStatusReport:
    message_id: str = ""
    original_message_id: str = ""
    status: str = ""
    reason: str = ""

    def build(self) -> str:
        root = ET.Element(_q("Document", NS_PACS002))
        fitf = _el("FIToFIPmtStsRpt", NS_PACS002)
        root.append(fitf)
        grp = _el("GrpHdr", NS_PACS002)
        grp.append(_el("MsgId", NS_PACS002, self.message_id))
        grp.append(_el("CreDtTm", NS_PACS002, datetime.now(timezone.utc).isoformat()))
        fitf.append(grp)
        orggr = _el("OrgnlGrpInf", NS_PACS002)
        orggr.append(_el("OrgnlMsgId", NS_PACS002, self.original_message_id))
        orggr.append(_el("OrgnlMsgNmId", NS_PACS002, "pacs.008.001.08"))
        fitf.append(orggr)
        sts = _el("TxInfAndSts", NS_PACS002)
        sts.append(_el("TxSts", NS_PACS002, self.status))
        if self.reason:
            rsn = _el("StsRsnInf", NS_PACS002)
            rsn.append(_el("Rsn", NS_PACS002))
            rsn.find(_q("Rsn", NS_PACS002)).append(_el("Cd", NS_PACS002, self.reason))
            sts.append(rsn)
        fitf.append(sts)
        ET.register_namespace("", NS_PACS002)
        return ET.tostring(root, encoding="unicode")

    def load(self, xml: str) -> dict:
        root = ET.fromstring(xml)
        fitf = _find_step(root, NS_PACS002, "FIToFIPmtStsRpt")
        sts = fitf.find(_q("TxInfAndSts", NS_PACS002))
        return {
            "message_id": _text(fitf.find(_q("GrpHdr", NS_PACS002)).find(_q("MsgId", NS_PACS002))),
            "status": _text(sts.find(_q("TxSts", NS_PACS002))),
        }


@dataclass
class AccountStatement:
    message_id: str = ""
    account_iban: str = ""
    statement_id: str = ""
    entries: list[dict] = field(default_factory=list)  # [{amount, currency, credit_debit, book_dt, reference}]

    def build(self) -> str:
        root = ET.Element(_q("Document", NS_CAMT053))
        stmt = _el("BkToCstmrStmt", NS_CAMT053)
        grp = _el("GrpHdr", NS_CAMT053)
        grp.append(_el("MsgId", NS_CAMT053, self.message_id))
        grp.append(_el("CreDtTm", NS_CAMT053, datetime.now(timezone.utc).isoformat()))
        stmt.append(grp)
        acct = _el("Acct", NS_CAMT053)
        acct.append(_el("Id", NS_CAMT053))
        acct.find(_q("Id", NS_CAMT053)).append(_el("IBAN", NS_CAMT053, self.account_iban))
        stmt.append(acct)
        for idx, entry in enumerate(self.entries):
            ntry = _el("Ntry", NS_CAMT053)
            ntry.append(_el("NtryRef", NS_CAMT053, entry.get("reference", f"ref{idx}")))
            ntry.append(_el("Amt", NS_CAMT053, f"{entry['amount']:.2f}"))
            ntry.find(_q("Amt", NS_CAMT053)).set("Ccy", entry.get("currency", "EUR"))
            ntry.append(_el("CdtDbtInd", NS_CAMT053, entry["credit_debit"]))
            ntry.append(_el("BookgDt", NS_CAMT053))
            ntry.find(_q("BookgDt", NS_CAMT053)).append(_el("Dt", NS_CAMT053, entry.get("book_dt", datetime.now(timezone.utc).date().isoformat())))
            stmt.append(ntry)
        root.append(stmt)
        ET.register_namespace("", NS_CAMT053)
        return ET.tostring(root, encoding="unicode")

    def load(self, xml: str) -> dict:
        root = ET.fromstring(xml)
        stmt = _find_step(root, NS_CAMT053, "BkToCstmrStmt")
        entries = []
        for ntry in stmt.findall(_q("Ntry", NS_CAMT053)):
            amount = ntry.find(_q("Amt", NS_CAMT053))
            entries.append(
                {
                    "amount": float(amount.text),
                    "currency": amount.get("Ccy", "EUR"),
                    "credit_debit": _text(ntry.find(_q("CdtDbtInd", NS_CAMT053))),
                    "reference": _text(ntry.find(_q("NtryRef", NS_CAMT053))),
                }
            )
        return {
            "message_id": _text(stmt.find(_q("GrpHdr", NS_CAMT053)).find(_q("MsgId", NS_CAMT053))),
            "account_iban": _text(stmt.find(_q("Acct", NS_CAMT053)).find(_q("Id", NS_CAMT053)).find(_q("IBAN", NS_CAMT053))),
            "entries": entries,
        }


def validate_iban(iban: str) -> bool:
    """Validation somme de contrôle IBAN (mod 97)."""
    s = (iban[4:] + iban[:4]).upper()
    if not s.isalnum():
        return False
    digits = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in s)
    return int(digits) % 97 == 1