import logging

from datetime import datetime, timedelta
from fastapi import status, HTTPException

from typing import List
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import UnmappedInstanceError
from sqlalchemy.future import select
from fastapi import Depends

from ..database import get_session
from .. import tables


logger = logging.getLogger(__name__)


class BaseService:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def get_or_404(
            self,
            table: tables.Base,
            wanted,
            column=None,
            wanted2=None,
            column2=None
    ) -> object:
        logger.debug('get_or_404')
        if column and column2:
            result = await self.session.execute(select(table)
                                                .where(column == wanted,
                                                       column2 == wanted2))
            entry = result.scalar()
        elif column:
            result = await self.session.execute(select(table)
                                                .where(column == wanted))
            entry = result.scalar()
        else:
            result = await self.session.get(entity=table, ident=wanted)
            entry = result

        if not entry:
            logger.warning(f'entry not found! wanted: %s -- table: %s-- column: %s', wanted, table, column)
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        logger.debug('Got entry: %s', entry)
        return entry

    async def get_many(self, table: tables.Base, wanted=None, column=None) -> List[object]:
        if wanted:
            result = await self.session.execute(select(table)
                                                .filter(column == wanted))
        else:
            result = await self.session.execute(select(table))
        entities = result.scalars().all()
        return entities

    async def create(self, table: tables.Base, data: dict) -> object:
        logger.debug('Create data: %s', data)
        entity = table(**data)
        self.session.add(entity)

        try:
            await self.session.commit()
            await self.session.refresh(entity)
        except IntegrityError as e:
            logger.warning(str(e))
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='most likely wrong id, or entity allready exist')

        return entity

    async def update(
            self,
            table: tables.Base,
            data: dict,
            wanted,
            column=None,
            wanted2=None,
            column2=None,
    ) -> object:
        logger.debug('update %s', data)
        if column2:
            update_query = update(table).where(column == wanted,
                                               column2 == wanted2)\
                .values(**data).returning(table)
        elif column:
            update_query = update(table).where(column == wanted)\
                .values(**data).returning(table)
        else:
            update_query = update(table).where(table.id == wanted)\
                .values(**data).returning(table)

        select_query = select(table)\
            .from_statement(update_query)\
            .execution_options(synchronize_session='fetch')  # WTF?

        logger.debug(select_query)

        try:
            entity = await self.session.scalar(select_query)
        except IntegrityError as e:
            logger.warning(str(e))
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='most likely wrong id')
        logger.debug(entity)

        try:
            await self.session.commit()
            await self.session.refresh(entity)
        except IntegrityError as e:
            logger.warning(str(e))
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='most likely wrong id')
        except UnmappedInstanceError as e:
            logger.warning(str(e))
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail='most likely wrong id')

        return entity

    async def delete(
            self,
            table: tables.Base,
            wanted,
            column=None,
            wanted2=None,
            column2=None,
    ):

        entry = await self.get_or_404(
            wanted=wanted,
            table=table,
            column=column,
            wanted2=wanted2,
            column2=column2,
        )
        logger.debug('entry to delete: %s', entry)

        await self.session.delete(entry)
        await self.session.commit()


def get_local_datetime_now(timezone_utc: int) -> datetime:
    return datetime.utcnow() + timedelta(hours=timezone_utc)


def get_datetime_utc(local_datetime: datetime, timezone_utc: int) -> datetime:
    return local_datetime - timedelta(hours=timezone_utc)
