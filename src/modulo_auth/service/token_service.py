import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt

ISSUER = "modulo-auth"


@dataclass(frozen=True)
class NewRefreshToken:
    token: str
    token_hash: str
    expires_at: datetime


class TokenService:

    def __init__(self, private_key: str, access_ttl: timedelta, refresh_ttl: timedelta):
        self._private_key = private_key
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl

    def issue_access_token(self, user_id: str) -> str:
        now = datetime.now(timezone.utc)
        return jwt.encode(
            {"iss": ISSUER, "sub": user_id, "iat": now, "exp": now + self._access_ttl},
            self._private_key,
            algorithm="RS256",
        )

    def new_refresh_token(self) -> NewRefreshToken:
        token = secrets.token_urlsafe(32)
        return NewRefreshToken(
            token=token,
            token_hash=self.hash_refresh_token(token),
            expires_at=datetime.now(timezone.utc) + self._refresh_ttl,
        )

    # Plain sha256 is enough: the token is 256 bits of randomness, not a guessable password.
    @staticmethod
    def hash_refresh_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()
