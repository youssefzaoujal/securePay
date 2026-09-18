"""Recettes DAB — ISO 8583, KaNest-lite, constructeurs."""

import pytest

from atm.iso8583 import PROC, RC, build_0200, from_iso_amount
from atm.kanest.runner import load_scenarios, run_all
from atm.profiles_loader import list_vendors, load_profile


def test_vendors_ncr_diebold_wnx_dn():
    assert set(list_vendors()) == {"ncr", "diebold", "wnx", "dn"}
    assert "NCR" in load_profile("ncr")["terminal_id_prefix"]


def test_iso8583_withdrawal_amount():
    msg = build_0200(
        scenario="withdrawal",
        pan="4111111111111111",
        amount=50,
        terminal_id="NCR0001",
        merchant_id="merchant-api",
    )
    assert msg["mti"] == "0200"
    assert msg["named"]["processing_code"] == PROC["withdrawal"]
    assert from_iso_amount(msg["named"]["amount"]) == 50.0


@pytest.mark.asyncio
async def test_kanest_recipes_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREPAY_ATM_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("SECUREPAY_ALM_DEFECTS", str(tmp_path / "alm.jsonl"))
    monkeypatch.setenv("SECUREPAY_PV_DIR", str(tmp_path))
    monkeypatch.setenv("LEGACY_CORE_URL", "")
    monkeypatch.setenv("SECUREPAY_EVENT_LOG", str(tmp_path / "events.jsonl"))

    async def _no_core(*_args, **_kwargs):
        return None

    monkeypatch.setattr("payment.legacy_client.call_legacy_core", _no_core)
    assert len(load_scenarios()) == 5
    report = await run_all()
    assert report["failed"] == 0
    assert report["passed"] == 5
    assert (tmp_path / "pv-recette-dab.html").exists()
