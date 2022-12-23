from typing import Type

from sqlalchemy import text, select

from fastapi import HTTPException, status

from workout_auth.db.repositories.base import BaseRepository
from workout_auth.db import tables
from workout_auth import models


class UsersRepository(BaseRepository[models.InUser, models.User, tables.User]):
    @property
    def _in_model(self) -> Type[models.InUser]:
        return models.InUser

    @property
    def _model(self) -> Type[models.User]:
        return models.User

    @property
    def _table(self) -> Type[tables.User]:
        return tables.User

    async def get_by_id(self, user_id: int) -> _model:
        user = await super().get_by_id(user_id)
        if user.deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{self._table.__name__} <id: {user_id}> deleted",
            )
        return user

    async def get_by_email(self, email: str) -> models.User | None:
        result = await self._db_session.execute(
            select(tables.User)
            .where(tables.User.email == email)
        )
        user = result.scalar()

        if not user:
            return

        return models.User.from_orm(user)

    async def delete(self, entry_id: int):
        await self._db_session.execute(
            text(
                "UPDATE :table SET deleted = true WHERE id = :entry_id"
            ),
            {
                'table': self._table.__name__,
                'entry_id': entry_id,
            }
        )
