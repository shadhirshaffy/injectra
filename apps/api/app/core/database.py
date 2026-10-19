
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry

from app.core.config import settings


database_url = URL.create(
    drivername="postgresql+psycopg",
    username=settings.database_user,
    password=settings.postgres_password,
    host=settings.database_host,
    port=settings.database_port,
    database=settings.database_name,
)

engine = create_engine(
    database_url,
    pool_pre_ping=True,
)

redis_client = Redis.from_url(
    settings.redis_url,
    decode_responses=True,
    socket_connect_timeout=1.0,
    socket_timeout=1.0,
    retry=Retry(NoBackoff(), 0),
    retry_on_timeout=False,
)


def test_postgres_connection() -> bool:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return True


def test_redis_connection() -> bool:
    return bool(redis_client.ping())


def get_session():
    from sqlalchemy.orm import Session

    with Session(engine) as session:
        try:
            yield session
            # Gateway scans explicitly commit before returning a decision.
            # Do not start a second commit after their completed transaction.
            if session.in_transaction():
                session.commit()
        except Exception:
            session.rollback()
            raise
