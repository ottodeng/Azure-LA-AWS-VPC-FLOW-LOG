from __future__ import annotations

import asyncio
from typing import Any

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier


class EntraTokenVerifier(TokenVerifier):
    """Validate Microsoft Entra JWT access tokens for the MCP resource server."""

    def __init__(self, issuer: str, audience: str) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        tenant_base = self.issuer.removesuffix("/v2.0")
        self.jwks_client = PyJWKClient(
            f"{tenant_base}/discovery/v2.0/keys",
            cache_keys=True,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            return await asyncio.to_thread(self._verify_sync, token)
        except Exception:
            return None

    def _verify_sync(self, token: str) -> AccessToken:
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        claims: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
        scopes = str(claims.get("scp", "")).split()
        roles = claims.get("roles", [])
        if isinstance(roles, list):
            scopes.extend(str(role) for role in roles)
        client_id = str(claims.get("azp") or claims.get("appid") or "unknown")
        subject = str(claims.get("oid") or claims.get("sub") or "unknown")
        audience = claims.get("aud")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=str(audience),
            subject=subject,
            claims=claims,
        )
