from modulo_auth.refresh_token_entity import RefreshTokenEntity
from modulo_auth.repository.refresh_token_repository import RefreshTokenRepository
from sqlalchemy.orm import Session
from sqlalchemy import select
from datetime import datetime

class DefaultRefreshTokenRepository(RefreshTokenRepository):

    def __init__(self, database: Session):
        self.database = database
    
    def create(self, user_id, token_hash, device_info, expires_at) -> RefreshTokenEntity:
        new_entity = RefreshTokenEntity()
        new_entity.user_id = user_id
        new_entity.token_hash = token_hash
        new_entity.device_info = device_info
        new_entity.expires_at = expires_at
        new_entity.issued_at = datetime.now()
        
        self.database.add(new_entity)
        self.database.commit()
        self.database.refresh(new_entity)
        
        return new_entity
    
    def get_by_hash(self, token_hash) -> RefreshTokenEntity:
        return self.database.scalars(
            select(RefreshTokenEntity)
                .where(RefreshTokenEntity.token_hash == token_hash)
        ).first()
    
    def revoke(self, id):
        token_to_revoke = self.database.scalars(
            select(RefreshTokenEntity)
                .where(RefreshTokenEntity.id == id)
        ).first()
        
        if token_to_revoke is None:
            return
        
        token_to_revoke.revoked_at = datetime.now()
        self.database.commit()

    def revoke_all_for_user(self, user_id):
        user_tokens = self.database.scalars(
            select(RefreshTokenEntity)
                .where(RefreshTokenEntity.user_id == user_id)
        ).all()

        for token in user_tokens:
            self.revoke(token.id)

        return