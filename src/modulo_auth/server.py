import logging
from concurrent import futures
from datetime import timedelta

import grpc
from modulo_common.grpc import auth_pb2_grpc

from modulo_auth.client.users_client import UsersClient
from modulo_auth.core.config import settings
from modulo_auth.core.database import SessionLocal
from modulo_auth.servicer.auth_servicer import AuthServicer
from modulo_auth.service.apple_verifier import AppleVerifier
from modulo_auth.service.token_service import TokenService


def serve() -> None:
    logging.basicConfig(level=logging.INFO)

    servicer = AuthServicer(
        users_client=UsersClient(settings.users_service_addr),
        apple_verifier=AppleVerifier(settings.apple_client_id),
        token_service=TokenService(
            settings.auth_private_key,
            access_ttl=timedelta(seconds=settings.access_token_ttl_seconds),
            refresh_ttl=timedelta(days=settings.refresh_token_ttl_days),
        ),
        session_factory=SessionLocal,
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    auth_pb2_grpc.add_AuthServiceServicer_to_server(servicer, server)
    server.add_insecure_port(f"[::]:{settings.grpc_port}")
    server.start()
    logging.info("Auth gRPC server listening on port %s", settings.grpc_port)
    server.wait_for_termination()
