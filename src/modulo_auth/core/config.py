from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")
    database_url: str
    auth_private_key: str
    auth_public_key: str
    users_service_addr: str
    apple_client_id: str
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_days: int = 30
    grpc_port: int = 50051

settings = Settings()
