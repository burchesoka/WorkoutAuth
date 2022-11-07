from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from workout_auth.settings import settings


DATABASE_URL = f'postgresql+asyncpg://{settings.db_user}:{settings.db_pass}@'\
               f'{settings.db_host}:{settings.db_port}/{settings.db_name}'

engine = create_async_engine(
    DATABASE_URL,
    echo=settings.dev,
    future=True,
)

async_session = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
