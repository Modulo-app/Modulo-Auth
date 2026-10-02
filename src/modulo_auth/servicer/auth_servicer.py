import logging
from collections.abc import Callable
from datetime import datetime, timezone

import grpc
from modulo_common.grpc import auth_pb2, auth_pb2_grpc
from sqlalchemy.orm import Session

from modulo_auth.client.users_client import UsersClient, UsersClientError, UsersUnavailableError
from modulo_auth.repository.default_refresh_token_repository import DefaultRefreshTokenRepository
from modulo_auth.service.apple_verifier import (
    AppleUnavailableError,
    AppleVerifier,
    InvalidAppleTokenError,
)
from modulo_auth.service.token_service import TokenService

logger = logging.getLogger(__name__)


class AuthServicer(auth_pb2_grpc.AuthServiceServicer):

    def __init__(
        self,
        users_client: UsersClient,
        apple_verifier: AppleVerifier,
        token_service: TokenService,
        session_factory: Callable[[], Session],
    ):
        self._users_client = users_client
        self._apple_verifier = apple_verifier
        self._token_service = token_service
        self._session_factory = session_factory

    def SignInWithApple(self, request, context):
        try:
            identity = self._apple_verifier.verify(request.identityToken)
        except InvalidAppleTokenError:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid Apple identity token")
        except AppleUnavailableError:
            context.abort(grpc.StatusCode.UNAVAILABLE, "Apple is unreachable")

        first_name = request.firstName if request.HasField("firstName") else None
        try:
            user = self._users_client.get_or_create_apple_user(identity.sub, identity.email, first_name)
        except UsersUnavailableError:
            context.abort(grpc.StatusCode.UNAVAILABLE, "Users service is unavailable")
        except UsersClientError:
            logger.exception("Users.GetOrCreate failed")
            context.abort(grpc.StatusCode.INTERNAL, "Could not resolve the user")

        refresh = self._token_service.new_refresh_token()
        with self._session_factory() as db:
            DefaultRefreshTokenRepository(db).create(
                user.id, refresh.token_hash, _device_info(context), refresh.expires_at
            )

        return auth_pb2.AppleUserResponse(
            userId=user.id,
            isNewAccount=user.isNewUser,
            tokens=auth_pb2.TokenResponse(
                accessToken=self._token_service.issue_access_token(user.id),
                refreshToken=refresh.token,
            ),
        )

    def RefreshToken(self, request, context):
        token_hash = self._token_service.hash_refresh_token(request.refreshToken)

        with self._session_factory() as db:
            repository = DefaultRefreshTokenRepository(db)
            stored = repository.get_by_hash(token_hash)
            if (
                stored is None
                or stored.revoked_at is not None
                or stored.expires_at <= datetime.now(timezone.utc)
            ):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid refresh token")

            user_id, device_info, stored_id = stored.user_id, stored.device_info, stored.id
            repository.revoke(stored_id)
            new_refresh = self._token_service.new_refresh_token()
            repository.create(user_id, new_refresh.token_hash, device_info, new_refresh.expires_at)

        return auth_pb2.TokenResponse(
            accessToken=self._token_service.issue_access_token(user_id),
            refreshToken=new_refresh.token,
        )


def _device_info(context) -> str:
    return dict(context.invocation_metadata()).get("x-device-info", "unknown")
