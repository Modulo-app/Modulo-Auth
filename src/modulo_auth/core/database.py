from collections.abc import Generator
from sqlalchemy.orm import Session

from modulo_common.core.database import make_session_factory
from modulo_auth.core.config import settings

SessionLocal = make_session_factory(settings.database_url)

def get_db() -> Generator[Session]:
    with SessionLocal() as db:
        yield db