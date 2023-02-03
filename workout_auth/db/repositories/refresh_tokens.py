from typing import Type

from sqlalchemy import select, delete

from workout_auth.db.repositories.base import BaseRepository
from workout_auth.db import tables
from workout_auth import models


class RefreshTokensRepository(BaseRepository[models.InRefreshToken, models.RefreshToken, tables.RefreshToken]):
    @property
    def _in_model(self) -> Type[models.InRefreshToken]:
        return models.InRefreshToken

    @property
    def _model(self) -> Type[models.RefreshToken]:
        return models.RefreshToken

    @property
    def _table(self) -> Type[tables.RefreshToken]:
        return tables.RefreshToken

    async def get_users_refresh_tokens(self, user_id: int) -> list[models.RefreshToken]:
        result = await self._db_session.execute(
            select(self._table)
            .where(self._table.user_id == user_id)
        )
        return [models.RefreshToken.from_orm(token) for token in result.scalars().all()]

    async def delete(self, entry_id: int):
        await self._db_session.execute(
            delete(self._table)
            .where(self._table.id == entry_id)
        )

    async def delete_by_refresh_token(self, refresh_token: models.RefreshTokenOnly):
        await self._db_session.execute(
            delete(self._table)
            .where(self._table.refresh_token == refresh_token.refresh_token)
        )

