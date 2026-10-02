from datetime import datetime
from uuid import uuid4

from modulo_common.core.base_entity import Base
from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

class RefreshTokenEntity(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: f"rt_{uuid4()}")
    user_id: Mapped[str] = mapped_column(String)
    token_hash: Mapped[str] = mapped_column(String)
    device_info: Mapped[str] = mapped_column(String)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)