import grpc

from modulo_common.grpc import users_pb2, users_pb2_grpc


class UsersClientError(Exception):
    pass


class UsersUnavailableError(UsersClientError):
    pass


class UsersClient:

    def __init__(self, addr: str, timeout: float = 5.0):
        self._channel = grpc.insecure_channel(addr)
        self._stub = users_pb2_grpc.UserServiceStub(self._channel)
        self._timeout = timeout

    def get_or_create_apple_user(
        self,
        apple_user_id: str,
        email: str | None,
        first_name: str | None,
    ) -> users_pb2.UserResponse:
        request = users_pb2.UserBody(
            email=email or "",
            provider=users_pb2.PROVIDER_TYPE_APPLE,
            providerId=apple_user_id,
        )
        
        if first_name is not None:
            request.firstName = first_name

        try:
            return self._stub.GetOrCreate(request, timeout=self._timeout)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                raise UsersUnavailableError("Users service is unavailable") from e
            raise UsersClientError(f"Users.GetOrCreate failed: {e.code()} {e.details()}") from e
