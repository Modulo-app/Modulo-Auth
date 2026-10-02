from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from modulo_auth.service.apple_verifier import APPLE_ISSUER, AppleVerifier, InvalidAppleTokenError

CLIENT_ID = "com.test.modulo"


@pytest.fixture
def apple_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def verifier(apple_key):
    verifier = AppleVerifier(CLIENT_ID)
    verifier._jwks_client = SimpleNamespace(
        get_signing_key_from_jwt=lambda token: SimpleNamespace(key=apple_key.public_key())
    )
    return verifier


def make_token(apple_key, **overrides):
    now = datetime.now(timezone.utc)
    claims = {
        "iss": APPLE_ISSUER,
        "aud": CLIENT_ID,
        "sub": "apple-sub-1",
        "email": "a@b.c",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        **overrides,
    }
    return jwt.encode(claims, apple_key, algorithm="RS256")


def test_accepts_a_valid_token(verifier, apple_key):
    identity = verifier.verify(make_token(apple_key))
    assert identity.sub == "apple-sub-1"
    assert identity.email == "a@b.c"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "com.someone.else"},
        {"iss": "https://evil.example.com"},
        {"exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
    ],
)
def test_rejects_wrong_audience_issuer_or_expired(verifier, apple_key, overrides):
    with pytest.raises(InvalidAppleTokenError):
        verifier.verify(make_token(apple_key, **overrides))
