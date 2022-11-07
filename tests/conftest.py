import os
import asyncio
from typing import AsyncGenerator, Generator, Callable

# rewriting db name before including database from database.py, to use test db in our tests
os.environ['DB_NAME'] = 'fastapi_test'  # DB have to be created manually
from workout_auth.db.database import async_session, engine, get_session
from workout_auth.db.tables import Base

import pytest_asyncio
from fastapi import FastAPI

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture(scope="session")
def event_loop(request) -> Generator:
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture()
async def db_session() -> AsyncSession:

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
        async with async_session(bind=connection) as session:
            yield session
            await session.flush()
            await session.rollback()


@pytest_asyncio.fixture()
def override_get_session(db_session: AsyncSession) -> Callable:
    async def _override_get_session():
        yield db_session

    return _override_get_session


@pytest_asyncio.fixture()
def app(override_get_session: Callable) -> FastAPI:
    from workout_auth.app import app

    app.dependency_overrides[get_session] = override_get_session
    return app


@pytest_asyncio.fixture()
async def async_client(app: FastAPI) -> AsyncGenerator:
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
