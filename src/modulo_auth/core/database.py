from modulo_common.core.database import make_session_factory
from modulo_auth.core.config import settings

SessionLocal = make_session_factory(settings.database_url)
