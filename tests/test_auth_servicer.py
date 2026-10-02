from concurrent import futures
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import grpc
import jwt
import pytest
from modulo_common.grpc import auth_pb2, auth_pb2_grpc, users_pb2

from modulo_auth.client.users_client import UsersUnavailableError
from modulo_auth.core.config import settings
from modulo_auth.core.database import SessionLocal
from modulo_auth.refresh_token_entity import RefreshTokenEntity
from modulo_auth.repository.default_refresh_token_repository import DefaultRefreshTokenRepository
from modulo_auth.servicer.auth_servicer import AuthServicer
from modulo_auth.service.apple_verifier import AppleIdentity, InvalidAppleTokenError
from modulo_auth.service.token_service import TokenService


class FakeVerifier:
    def verify(self, identity_token):
        if identity_token == "bad":
            raise InvalidAppleTokenError("bad token")
        return AppleIdentity(sub="apple-sub", email="a@b.c")


class FakeUsers:
    def __init__(self):
        self.down = False
        self.user_id = f"usr_test_{uuid4()}"

    def get_or_create_apple_user(self, apple_user_id, email, first_name):
        if self.down:
            raise UsersUnavailableError("down")
        return users_pb2.UserResponse(id=self.user_id, isNewUser=True)


@pytest.fixture
def users():
    return FakeUsers()


@pytest.fixture
def stub(users):
    token_service = TokenService(settings.auth_private_key, timedelta(minutes=15), timedelta(days=30))
    servicer = AuthServicer(users, FakeVerifier(), token_service, SessionLocal)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    auth_pb2_grpc.add_AuthServiceServicer_to_server(servicer, server)
    port = server.add_insecure_port("localhost:0")
    server.start()
    with grpc.insecure_channel(f"localhost:{port}") as channel:
        yield auth_pb2_grpc.AuthServiceStub(channel)
    server.stop(None)
    with SessionLocal() as db:
        db.query(RefreshTokenEntity).filter(RefreshTokenEntity.user_id == users.user_id).delete()
        db.commit()


def sign_in(stub, identity_token="ok"):
    return stub.SignInWithApple(
        auth_pb2.AppleUserBody(identityToken=identity_token, authorizationCode="code")
    )


def refresh(stub, token):
    return stub.RefreshToken(auth_pb2.RefreshTokenBody(refreshToken=token))


def test_sign_in_issues_verifiable_access_token_and_stores_session(stub, users):
    response = sign_in(stub)

    assert response.userId == users.user_id
    assert response.isNewAccount
    claims = jwt.decode(
        response.tokens.accessToken, settings.auth_public_key, algorithms=["RS256"], issuer="modulo-auth"
    )
    assert claims["sub"] == users.user_id
    with SessionLocal() as db:
        stored = DefaultRefreshTokenRepository(db).get_by_hash(
            TokenService.hash_refresh_token(response.tokens.refreshToken)
        )
        assert stored.user_id == users.user_id
        assert stored.revoked_at is None


def test_refresh_rotates_the_token_and_rejects_the_old_one(stub):
    first = sign_in(stub).tokens
    second = refresh(stub, first.refreshToken)

    assert second.refreshToken != first.refreshToken
    refresh(stub, second.refreshToken)
    with pytest.raises(grpc.RpcError) as error:
        refresh(stub, first.refreshToken)
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_refresh_rejects_an_expired_token(stub, users):
    expired = TokenService(settings.auth_private_key, timedelta(minutes=15), timedelta(days=-1))
    new = expired.new_refresh_token()
    with SessionLocal() as db:
        DefaultRefreshTokenRepository(db).create(users.user_id, new.token_hash, "iphone", new.expires_at)

    with pytest.raises(grpc.RpcError) as error:
        refresh(stub, new.token)
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_sign_in_rejects_an_invalid_apple_token(stub):
    with pytest.raises(grpc.RpcError) as error:
        sign_in(stub, identity_token="bad")
    assert error.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_sign_in_reports_users_unavailable(stub, users):
    users.down = True
    with pytest.raises(grpc.RpcError) as error:
        sign_in(stub)
    assert error.value.code() == grpc.StatusCode.UNAVAILABLE
