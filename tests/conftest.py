import os
import asyncio
from typing import AsyncGenerator, Generator, Callable

import pytest
import pytest_asyncio
from fastapi import FastAPI

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from workout_auth.tables import Base


@pytest.fixture(scope="session")
def event_loop(request) -> Generator:
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture()
async def db_session() -> AsyncSession:
    # rewriting db name before including database from database.py, to use test db in our tests
    os.environ['DB_NAME'] = 'fastapi_test'  # DB have to be created manually
    from workout_auth.database import async_session, engine

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
        async with async_session(bind=connection) as session:
            yield session
            await session.flush()
            await session.rollback()


@pytest_asyncio.fixture()
def override_get_db(db_session: AsyncSession) -> Callable:
    async def _override_get_db():
        yield db_session

    return _override_get_db


@pytest.fixture()
def app(override_get_db: Callable) -> FastAPI:
    from workout_auth.database import get_session
    from workout_auth.app import app

    app.dependency_overrides[get_session] = override_get_db
    return app


@pytest_asyncio.fixture()
async def async_client(app: FastAPI) -> AsyncGenerator:
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
