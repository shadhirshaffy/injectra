from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from redis.exceptions import ConnectionError

from app.core.auth import get_admin
from app.core.config import Settings
from app.core.database import redis_client
from app.core.errors import APIError
from app.core.management_admission import (ManagementRateLimiter, get_management_limiter,
    management_source_admission, management_user_admission)
from app.main import app
from app.models import Organization
from sqlalchemy import select


@pytest.fixture
def limiters():
    prefix = "injectra:test-management:" + uuid4().hex
    keys = set()
    class Tracked(ManagementRateLimiter):
        def bucket_key(self, scope, identifier):
            key = super().bucket_key(scope, identifier)
            keys.add(key)
            return key
    def make(limit=2):
        return Tracked(redis_client, limit, 60, prefix)
    yield make
    if keys:
        assert all(key.startswith(prefix + ":") for key in keys)
        redis_client.delete(*keys)


def loopback_client():
    async def wrapped(scope, receive, send):
        if scope["type"] == "http":
            scope["client"] = ("127.0.0.1", 50000)
        await app(scope, receive, send)
    return TestClient(wrapped)


def test_source_denial_precedes_auth_and_ignores_forwarded_headers(client, limiters):
    limiter = limiters(1)
    app.dependency_overrides[get_management_limiter] = lambda: dict.fromkeys(("source", "user", "write"), limiter)
    calls = []
    def unauthorized():
        calls.append(True)
        raise APIError(401, "unauthenticated", "Authentication required.")
    app.dependency_overrides[get_admin] = unauthorized
    with loopback_client() as http:
        assert http.get("/api/v1/organizations").status_code == 401
        response = http.get("/api/v1/organizations", headers={"X-Forwarded-For": "203.0.113.5"})
        assert response.status_code == 429
        assert response.headers["Retry-After"]
        assert response.headers["Cache-Control"] == "no-store"
        assert len(calls) == 1
        assert http.get("/api/v1/health").status_code == 200


def test_write_quota_blocks_mutation_and_reads_still_work(client, db, limiters):
    controls = {"source": limiters(100), "user": limiters(100), "write": limiters(1)}
    app.dependency_overrides[get_management_limiter] = lambda: controls
    with loopback_client() as http:
        assert http.post("/api/v1/organizations", json={"name": "First"}).status_code == 201
        response = http.post("/api/v1/organizations", json={"name": "Second"})
        assert response.status_code == 429
        assert db.scalar(select(Organization).where(Organization.name == "Second")) is None
        assert http.get("/api/v1/organizations").status_code == 200
        assert http.get("/api/v1/me").status_code == 200


def test_user_quota_shared_across_routes_and_isolated_by_identity(client, limiters):
    controls = {"source": limiters(100), "user": limiters(1), "write": limiters(100)}
    app.dependency_overrides[get_management_limiter] = lambda: controls
    with loopback_client() as http:
        assert http.get("/api/v1/organizations").status_code == 200
        assert http.get("/api/v1/me").status_code == 429
    assert controls["user"].admit("user", uuid4()).remaining == 0


def test_redis_outage_blocks_before_auth_without_leaking_errors(client):
    def broken(*args):
        raise ConnectionError("private credential")
    limiter = ManagementRateLimiter(SimpleNamespace(eval=broken), 1, 60, "test")
    app.dependency_overrides[get_management_limiter] = lambda: dict.fromkeys(("source", "user", "write"), limiter)
    app.dependency_overrides[get_admin] = lambda: pytest.fail("Outage reached identity provider")
    with loopback_client() as http:
        response = http.get("/api/v1/organizations")
        assert response.status_code == 503 and "private" not in response.text


def test_shared_atomic_capacity_and_private_keys(limiters):
    limiter = limiters(7)
    user = uuid4()
    def attempt(_):
        try:
            limiter.admit("user", user)
            return 200
        except APIError as exc:
            return exc.status
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(attempt, range(30)))
    assert results.count(200) == 7 and results.count(429) == 23
    assert str(user) not in limiter.bucket_key("user", user)
    assert "127.0.0.1" not in limiter.bucket_key("source", "127.0.0.1")
    assert limiter.bucket_key("source", "::1") == limiter.bucket_key("source", "0:0:0:0:0:0:0:1")
    assert limiter.bucket_key("user", user) != limiter.bucket_key("write", user)


def test_all_management_routes_have_controls():
    from fastapi.routing import APIRoute
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        controls = {dependency.call for dependency in route.dependant.dependencies}
        if route.path in {"/api/v1/health", "/api/v1/gateway/scan"}:
            assert management_source_admission not in controls
        else:
            assert management_source_admission in controls, route.path
            assert management_user_admission in controls, route.path


@pytest.mark.parametrize("scope,identifier", [("source", "not-an-ip"), ("user", "unverified"), ("unknown", uuid4())])
def test_unverified_bucket_identity_fails_closed(limiters, scope, identifier):
    with pytest.raises(APIError) as exc:
        limiters().admit(scope, identifier)
    assert exc.value.status == 503


@pytest.mark.parametrize("field,value", [("management_source_limit_requests", 0),
    ("management_user_limit_requests", 1000001), ("management_write_limit_requests", -1),
    ("management_rate_limit_window_seconds", 3601), ("management_rate_limit_prefix", "bad prefix")])
def test_configuration_bounds(field, value):
    with pytest.raises(ValidationError):
        Settings(postgres_password="test", _env_file=None, **{field: value})
