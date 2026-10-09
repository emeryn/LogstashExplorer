from collections.abc import AsyncIterator

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.core.secrets import require_secret

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine() -> None:
    global _engine, _sessionmaker
    s = get_settings()
    url = URL.create(
        "postgresql+asyncpg",
        username=s.db_user,
        password=require_secret("db_password"),
        host=s.db_host,
        port=s.db_port,
        database=s.db_name,
    )
    _engine = create_async_engine(url, pool_size=10, max_overflow=5, pool_pre_ping=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)


def get_engine():
    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        raise RuntimeError("database not initialised")
    return _sessionmaker


async def get_db() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as session:
        yield session
