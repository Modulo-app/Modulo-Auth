from dataclasses import dataclass

import jwt
from jwt.exceptions import PyJWKClientConnectionError, PyJWTError

APPLE_ISSUER = "https://appleid.apple.com"
APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys"


class InvalidAppleTokenError(Exception):
    pass


class AppleUnavailableError(Exception):
    pass


@dataclass(frozen=True)
class AppleIdentity:
    sub: str
    email: str | None


class AppleVerifier:

    def __init__(self, client_id: str):
        self._client_id = client_id
        self._jwks_client = jwt.PyJWKClient(APPLE_JWKS_URL)

    def verify(self, identity_token: str) -> AppleIdentity:
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(identity_token)
            claims = jwt.decode(
                identity_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=APPLE_ISSUER,
                options={"require": ["exp", "iat", "sub"]},
            )
        # Must come before PyJWTError: it is a subclass, and Apple being down is not a bad token.
        except PyJWKClientConnectionError as e:
            raise AppleUnavailableError("Cannot fetch Apple public keys") from e
        except PyJWTError as e:
            raise InvalidAppleTokenError(str(e)) from e

        return AppleIdentity(sub=claims["sub"], email=claims.get("email"))
