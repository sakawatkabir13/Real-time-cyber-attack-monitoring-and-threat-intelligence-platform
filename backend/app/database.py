from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy.engine import make_url
from app.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    connect_args={"ssl": settings.DATABASE_SSL},
)
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()


def sync_database_url() -> str:
    """Return the configured database URL using psycopg's synchronous driver."""
    url = make_url(settings.DATABASE_URL)
    if url.get_backend_name() == "postgresql":
        url = url.set(drivername="postgresql+psycopg")
    return url.render_as_string(hide_password=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
