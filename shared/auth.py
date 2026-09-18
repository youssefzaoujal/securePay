"""Validation JWT RS256 via JWKS Keycloak + anti-replay (jti) + scopes."""

from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwk, jwt
from jose.exceptions import JWTError

from config import get_settings
from shared.events import emit_event

security = HTTPBearer(auto_error=True)

_JWKS_CACHE: dict[str, Any] = {"keys": None, "fetched_at": 0.0}
_JTI_SEEN: dict[str, float] = {}
JWKS_TTL_SECONDS = 300
REPLAY_WINDOW_SECONDS = 1800


class TokenClaims(dict):
    """Claims JWT avec accès attributaire."""

    @property
    def merchant_id(self) -> str:
        return (
            self.get("merchant_id")
            or self.get("azp")
            or self.get("client_id")
            or self.get("preferred_username")
            or ""
        )

    @property
    def roles(self) -> list[str]:
        realm = self.get("realm_access") or {}
        resource = self.get("resource_access") or {}
        client_roles: list[str] = []
        for client in resource.values():
            client_roles.extend(client.get("roles", []))
        scopes = str(self.get("scope") or "").split()
        return list({*realm.get("roles", []), *client_roles, *scopes})

    @property
    def subject(self) -> str:
        return str(self.get("sub") or self.merchant_id)


async def _fetch_jwks() -> dict[str, Any]:
    now = time.time()
    if _JWKS_CACHE["keys"] and now - _JWKS_CACHE["fetched_at"] < JWKS_TTL_SECONDS:
        return _JWKS_CACHE["keys"]

    settings = get_settings()
    url = (
        f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}"
        "/protocol/openid-connect/certs"
    )
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        keys = response.json()
    _JWKS_CACHE["keys"] = keys
    _JWKS_CACHE["fetched_at"] = now
    return keys


def _signing_key(token: str, jwks: dict[str, Any]):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    for key_data in jwks.get("keys", []):
        if key_data.get("kid") == kid:
            return jwk.construct(key_data)
    if jwks.get("keys"):
        return jwk.construct(jwks["keys"][0])
    raise JWTError("Aucune clé JWKS disponible")


def _reject_replay(claims: dict[str, Any]) -> None:
    jti = claims.get("jti")
    if not jti:
        return
    now = time.time()
    expired = [key for key, exp in _JTI_SEEN.items() if exp < now]
    for key in expired:
        _JTI_SEEN.pop(key, None)
    if jti in _JTI_SEEN:
        emit_event(
            {
                "event_type": "jwt_replay",
                "scenario": "jwt_replay",
                "status": "blocked",
                "jti": jti,
                "detection_signal": "jwt_jti_reuse",
            }
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT replay détecté (jti déjà utilisé)",
        )
    exp = float(claims.get("exp") or (now + REPLAY_WINDOW_SECONDS))
    _JTI_SEEN[jti] = exp


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> TokenClaims:
    """Valide signature RS256, issuer, expiry, puis anti-replay jti."""
    settings = get_settings()
    token = credentials.credentials
    try:
        jwks = await _fetch_jwks()
        key = _signing_key(token, jwks)
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={
                "verify_aud": False,
                "verify_at_hash": False,
                # Lab: Keycloak issuer is http://keycloak:8080 vs localhost:8081.
                "verify_iss": settings.APP_ENV not in {"lab", "test"},
            },
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
        ) from exc

    _reject_replay(claims)
    result = TokenClaims(claims)
    try:
        credentials.claims = result  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        # FastAPI < 0.136 : HTTPAuthorizationCredentials n'a pas de champ
        # `claims` — l'attribut est un confort, aucun appelant ne le lit.
        pass
    return result


def require_role(*required_roles: str):
    async def role_checker(claims: TokenClaims = Depends(verify_token)) -> TokenClaims:
        roles = claims.roles
        if not any(role in roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rôle requis: {', '.join(required_roles)}",
            )
        return claims

    return role_checker


def require_scope(*required_scopes: str):
    async def scope_checker(claims: TokenClaims = Depends(verify_token)) -> TokenClaims:
        scopes = set(str(claims.get("scope") or "").split())
        if not any(scope in scopes for scope in required_scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Scope requis: {', '.join(required_scopes)}",
            )
        return claims

    return scope_checker
