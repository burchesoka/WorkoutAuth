from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from .settings import settings


engine = create_async_engine(
    f'postgresql+asyncpg://{settings.db_user}:{settings.db_pass}@'
    f'{settings.db_host}:{settings.db_port}/{settings.db_name}',
    echo=settings.dev,
    future=True,
)


async def get_session() -> AsyncSession:
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session
