import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from aws_vpc_flow_mcp.auth import EntraTokenVerifier


class SigningKey:
    def __init__(self, key):
        self.key = key


@pytest.mark.asyncio
async def test_entra_token_verifier_maps_scope_role_and_subject():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://login.microsoftonline.com/example-tenant/v2.0"
    audience = "api://example-mcp"
    now = int(time.time())
    encoded = jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + 3600,
            "oid": "analyst-object-id",
            "azp": "openclaw-client-id",
            "scp": "aws_vpc_flow.read",
            "roles": ["AWSVPCFlow.SecurityAnalyst"],
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = EntraTokenVerifier(issuer, audience)
    verifier.jwks_client = type(
        "FakeJwks",
        (),
        {"get_signing_key_from_jwt": lambda self, token: SigningKey(private_key.public_key())},
    )()
    token = await verifier.verify_token(encoded)
    assert token is not None
    assert token.subject == "analyst-object-id"
    assert "aws_vpc_flow.read" in token.scopes
    assert "AWSVPCFlow.SecurityAnalyst" in token.scopes


@pytest.mark.asyncio
async def test_entra_token_verifier_rejects_wrong_audience():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = "https://login.microsoftonline.com/example-tenant/v2.0"
    now = int(time.time())
    encoded = jwt.encode(
        {
            "iss": issuer,
            "aud": "api://wrong",
            "iat": now,
            "exp": now + 3600,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test"},
    )
    verifier = EntraTokenVerifier(issuer, "api://expected")
    verifier.jwks_client = type(
        "FakeJwks",
        (),
        {"get_signing_key_from_jwt": lambda self, token: SigningKey(private_key.public_key())},
    )()
    assert await verifier.verify_token(encoded) is None
