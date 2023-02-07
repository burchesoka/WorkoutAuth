from abc import ABCMeta, abstractmethod
import logging
from typing import Generic, TypeVar, Type
from uuid import uuid4, UUID

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select, update

from workout_auth.db.errors import DoesNotExist
from workout_auth.db.database import get_session
from workout_auth.models.base import MyBaseModel


IN_MODEL = TypeVar("IN_MODEL", bound=MyBaseModel)
MODEL = TypeVar("MODEL", bound=MyBaseModel)
TABLE = TypeVar("TABLE")


logger = logging.getLogger(__name__)


class BaseRepository(Generic[IN_MODEL, MODEL, TABLE], metaclass=ABCMeta):
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self._db_session = session

    @property
    @abstractmethod
    def _table(self) -> Type[TABLE]:
        ...

    @property
    @abstractmethod
    def _model(self) -> Type[MODEL]:
        ...

    async def create(self, in_model: IN_MODEL) -> MODEL:
        entry = self._table(**in_model.dict())
        self._db_session.add(entry)

        try:
            await self._db_session.commit()
            await self._db_session.refresh(entry)
        except IntegrityError as e:
            logger.warning(str(e))
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='most likely wrong id, or entity already exist')

        return self._model.from_orm(entry)

    async def get_by_id(self, entry_id: int) -> MODEL:
        entry = await self._db_session.get(self._table, entry_id)
        if not entry:
            logger.debug("%s <id: %s> does not exist", self._table.__name__, entry_id)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{self._table.__name__} <id: {entry_id}> does not exist",
            )
        return self._model.from_orm(entry)

    async def update(self, entry_id: int, entry_data: IN_MODEL) -> MODEL:
        logger.debug('update <%s> id: %s, data: %s', self._table.__name__, entry_id, entry_data)

        update_query = update(self._table).where(self._table.id == entry_id)\
            .values(**entry_data.dict()).returning(self._table)

        select_query = select(self._table)\
            .from_statement(update_query)\
            .execution_options(synchronize_session='fetch')

        logger.debug(select_query)

        try:
            entity = await self._db_session.scalar(select_query)
        except IntegrityError as e:
            logger.warning(str(e))
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='most likely wrong id')
        logger.debug(entity)

        return self._model.from_orm(entity)

    @abstractmethod
    async def delete(self, entry_id: int):
        """ Delete from DB, or set deleted = true """
