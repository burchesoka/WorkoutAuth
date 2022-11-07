import abc
import logging
from typing import Generic, TypeVar, Type
from uuid import uuid4, UUID

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from workout_auth.db.errors import DoesNotExist
from workout_auth.db.database import get_session
from workout_auth.models.base import BaseSchema


IN_SCHEMA = TypeVar("IN_SCHEMA", bound=BaseSchema)
SCHEMA = TypeVar("SCHEMA", bound=BaseSchema)
TABLE = TypeVar("TABLE")


logger = logging.getLogger(__name__)


class BaseRepository(Generic[IN_SCHEMA, SCHEMA, TABLE], metaclass=abc.ABCMeta):
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self._db_session = session

    @property
    @abc.abstractmethod
    def _table(self) -> Type[TABLE]:
        ...

    @property
    @abc.abstractmethod
    def _schema(self) -> Type[SCHEMA]:
        ...

    async def create(self, in_schema: IN_SCHEMA) -> SCHEMA:
        entry = self._table(id=uuid4(), **in_schema.dict())
        self._db_session.add(entry)
        await self._db_session.commit()
        return self._schema.from_orm(entry)

    async def get_by_id(self, entry_id: int) -> SCHEMA:
        entry = await self._db_session.get(self._table, entry_id)
        if not entry:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{self._table.__name__} <id:{entry_id}> does not exist",
            )
        return self._schema.from_orm(entry)
