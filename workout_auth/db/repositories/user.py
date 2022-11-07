from typing import Type

from workout_auth.db.repositories.base import BaseRepository
from workout_auth.db import tables
from workout_auth import models


class UsersRepository(BaseRepository[models.UserCreate, models.User, tables.User]):
    @property
    def _in_schema(self) -> Type[models.UserCreate]:
        return models.UserCreate

    @property
    def _schema(self) -> Type[models.User]:
        return models.User

    @property
    def _table(self) -> Type[tables.User]:
        return tables.User
