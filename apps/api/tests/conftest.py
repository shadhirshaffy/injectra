from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.core.auth import get_admin
from app.core.config import settings
from app.core.database import database_url, engine, get_session
from app.main import app
from app.models import User
from app.core.rate_limit import Admission, get_gateway_limiter
from app.core.management_admission import get_management_limiter


@pytest.fixture(autouse=True)
def isolated_management_admission():
    # Dedicated admission tests replace this; unrelated auth tests require no Redis.
    class AllowManagement:
        def admit(self, scope, identifier):
            return Admission(300, 299, 60)
    app.dependency_overrides[get_management_limiter] = lambda: dict.fromkeys(("source", "user", "write"), AllowManagement())
    yield
    app.dependency_overrides.pop(get_management_limiter, None)


@pytest.fixture(scope="session")
def migrated_engine():
    schema = "test_phase2_" + uuid4().hex
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated = create_engine(database_url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
        config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "migrations"))
        with isolated.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            command.check(config)
        yield isolated
    finally:
        isolated.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


@pytest.fixture
def db(migrated_engine):
    with migrated_engine.connect() as connection:
        transaction = connection.begin()
        with Session(bind=connection, join_transaction_mode="create_savepoint") as session:
            yield session
        transaction.rollback()


@pytest.fixture
def client(db, monkeypatch):
    monkeypatch.setattr(settings, "api_key_pepper", SecretStr("test-pepper-" + "p" * 32))
    user = User(identity_subject="test-owner")
    db.add(user)
    db.flush()
    db.commit()

    def request_session():
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise

    app.dependency_overrides[get_session] = request_session
    app.dependency_overrides[get_admin] = lambda: user
    # Non-admission tests remain independent of Redis. Dedicated integration
    # tests replace this override with the real atomic Redis limiter.
    class AllowAdmission:
        def check(self, identity):
            return Admission(60, 59, 60)
    app.dependency_overrides[get_gateway_limiter] = lambda: AllowAdmission()
    with TestClient(app) as test_client:
        test_client.admin_user = user
        yield test_client
    app.dependency_overrides.clear()
