"""Gateway authentication — réexport du noyau JWKS/BOLA."""

from shared.auth import TokenClaims, require_role, require_scope, verify_token

__all__ = ["verify_token", "require_role", "require_scope", "TokenClaims"]
