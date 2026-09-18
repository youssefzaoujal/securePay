"""Tests BOLA — le merchant_id JWT gagne toujours contre le body."""

import pytest
from fastapi import HTTPException

from shared.auth import TokenClaims
from shared.bola import assert_object_owner, bind_merchant_id


def _merchant(client_id: str = "merchant-api") -> TokenClaims:
    return TokenClaims({"azp": client_id, "client_id": client_id, "realm_access": {"roles": []}})


class TestBola:
    def test_bind_accepts_matching_body(self):
        assert bind_merchant_id(_merchant(), "merchant-api") == "merchant-api"

    def test_bind_rejects_spoofed_merchant_id(self):
        with pytest.raises(HTTPException) as exc:
            bind_merchant_id(_merchant(), "MERCH_999")
        assert exc.value.status_code == 403
        assert "BOLA" in str(exc.value.detail)

    def test_object_owner_blocks_cross_tenant_read(self):
        with pytest.raises(HTTPException) as exc:
            assert_object_owner(
                _merchant(),
                "other-merchant",
                resource_type="transaction",
                resource_id="pay_abc",
            )
        assert exc.value.status_code == 403

    def test_admin_bypasses_object_owner(self):
        admin = TokenClaims(
            {"azp": "admin-console", "realm_access": {"roles": ["admin"]}}
        )
        assert_object_owner(
            admin,
            "other-merchant",
            resource_type="transaction",
            resource_id="pay_abc",
        )
