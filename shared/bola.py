"""Contrôle d'accès object-level — défense explicite contre BOLA/IDOR (OWASP API1)."""

from __future__ import annotations

from fastapi import HTTPException, status

from shared.auth import TokenClaims
from shared.events import emit_event


def assert_object_owner(
    claims: TokenClaims,
    resource_merchant_id: str,
    *,
    resource_type: str,
    resource_id: str,
    source_ip: str = "",
) -> None:
    """Refuse l'accès si le merchant JWT n'est pas propriétaire de la ressource.

    Les rôles admin / service-account bypasse le filtre (audit inclus).
    """
    roles = claims.roles
    if "admin" in roles or "realm-admin" in roles:
        return

    caller = claims.merchant_id
    if not caller or caller != resource_merchant_id:
        emit_event(
            {
                "event_type": "authorization_error",
                "scenario": "bola",
                "status": "blocked",
                "status_code": 403,
                "error_type": "object_level_authorization",
                "source_ip": source_ip,
                "merchant_id": caller,
                "target_merchant_id": resource_merchant_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "detection_signal": "cross_merchant_access_denied",
            }
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès refusé: ressource hors périmètre merchant (BOLA blocked)",
        )


def bind_merchant_id(claims: TokenClaims, body_merchant_id: str | None) -> str:
    """Le merchant_id fait foi depuis le JWT, jamais depuis le body client.

    Si le body tente d'usurper un autre merchant_id → 403 + événement BOLA.
    """
    token_merchant = claims.merchant_id
    if body_merchant_id and body_merchant_id != token_merchant:
        emit_event(
            {
                "event_type": "authorization_error",
                "scenario": "bola",
                "status": "blocked",
                "status_code": 403,
                "error_type": "merchant_id_spoofing",
                "merchant_id": token_merchant,
                "target_merchant_id": body_merchant_id,
                "detection_signal": "cross_merchant_access_denied",
            }
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="merchant_id du body ne correspond pas au JWT (BOLA blocked)",
        )
    if not token_merchant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Impossible de dériver merchant_id depuis le JWT",
        )
    return token_merchant
