from collections.abc import AsyncGenerator

from sqlmodel.ext.asyncio.session import AsyncSession

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from .config import settings

async_engine = create_async_engine(settings.DATABASE_URL, echo=settings.DATABASE_ECHO)


AsyncSessionLocal = async_sessionmaker(
    bind=async_engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
