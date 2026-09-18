"""Tests HSM simulé (Phase 3) — non-extractabilité, CAVV, KEK, façade backend."""

from __future__ import annotations

import pytest

from hsm.service import HSMError, SoftwareHSM, get_hsm


@pytest.fixture
def hsm():
    return SoftwareHSM()


def test_provision_and_sign(hsm):
    kid = hsm.provision_key(purpose="cavv")
    sig = hsm.sign(kid, b"transaction-data")
    assert len(sig) == 32


def test_sign_cavv_format(hsm):
    kid = hsm.provision_key(purpose="cavv")
    cavv = hsm.sign_cavv(kid, "3DSMessage|transid|amount")
    assert len(cavv) == 28  # 21 octets → base64


def test_cavv_deterministic(hsm):
    kid = hsm.provision_key(purpose="cavv")
    value = "fixed"
    assert hsm.sign_cavv(kid, value) == hsm.sign_cavv(kid, value)


def test_export_refused(hsm):
    kid = hsm.provision_key(purpose="cavv")
    with pytest.raises(HSMError):
        hsm.export_key(kid)


def test_sign_unknown_key_raises(hsm):
    with pytest.raises(HSMError):
        hsm.sign("nope", b"x")


def test_kek_provision(hsm):
    kid = hsm.generate_kek()
    assert kid.startswith("key_")


def test_get_hsm_actually_returns_hsm():
    from hsm.service import _find_softhsm_lib, SoftHSMBackend

    hsm = get_hsm()
    if not _find_softhsm_lib():
        assert isinstance(hsm, SoftwareHSM)