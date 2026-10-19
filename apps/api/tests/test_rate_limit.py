from concurrent.futures import ThreadPoolExecutor
from time import sleep
from types import SimpleNamespace
from uuid import UUID, uuid4

from pydantic import ValidationError
import pytest
from redis.exceptions import ConnectionError, ResponseError
from sqlalchemy import select

from app.api import gateway
from app.core.config import Settings
from app.core.database import redis_client
from app.core.errors import APIError
from app.core.rate_limit import GatewayRateLimiter, get_gateway_limiter
from app.main import app
from app.models import SecurityEvent
from test_management import issue_key


def identity():
    return SimpleNamespace(organization=SimpleNamespace(id=uuid4()), application=SimpleNamespace(id=uuid4()))


@pytest.fixture
def real_limiter():
    # One random namespace per test. No FLUSHDB, wildcard deletion, or app keys.
    redis_client.ping()
    prefix = "injectra:test-rate:" + uuid4().hex
    keys = set()

    class TrackedLimiter(GatewayRateLimiter):
        def key(self, org, app):
            result = super().key(org, app)
            keys.add(result)
            return result

    def make(limit=2, window=60):
        return TrackedLimiter(redis_client, limit, window, prefix)

    yield make
    assert all(key.startswith(prefix + ":") for key in keys)
    if keys:
        redis_client.delete(*keys)


def test_atomic_quota_and_expiration(real_limiter):
    limiter, actor = real_limiter(), identity()
    first = limiter.check(actor)
    assert first.limit == 2 and first.remaining == 1 and first.reset_after_seconds == 60
    assert limiter.check(actor).remaining == 0
    key = limiter.key(actor.organization.id, actor.application.id)
    ttl = redis_client.pttl(key)
    with pytest.raises(APIError) as exc:
        limiter.check(actor)
    assert exc.value.status == 429 and 1 <= int(exc.value.headers["Retry-After"]) <= 60
    assert redis_client.get(key) == "2" and 0 <= redis_client.pttl(key) <= ttl
    redis_client.pexpire(key, 1)
    sleep(0.02)
    assert limiter.check(actor).remaining == 1


def test_multiple_workers_share_exact_capacity(real_limiter):
    actor = identity()
    workers = [real_limiter(limit=7) for _ in range(4)]

    def attempt(index):
        try:
            workers[index % 4].check(actor)
            return 200
        except APIError as exc:
            return exc.status

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(40)))
    assert results.count(200) == 7 and results.count(429) == 33


def test_applications_and_organizations_are_isolated(real_limiter):
    limiter = real_limiter(limit=1)
    actor = identity()
    limiter.check(actor)
    other_app = SimpleNamespace(organization=actor.organization, application=SimpleNamespace(id=uuid4()))
    other_org = SimpleNamespace(organization=SimpleNamespace(id=uuid4()), application=actor.application)
    assert limiter.check(other_app).remaining == 0
    assert limiter.check(other_org).remaining == 0
    with pytest.raises(APIError):
        limiter.check(actor)


@pytest.mark.parametrize("state,expiry", [("bad", 60), ("0", 60), ("-1", 60), ("1.5", 60),
    ("1", None), ("1e0", 60), ("9999999999999", 60), ("3", 60), ("01", 60)])
def test_corrupt_redis_state_fails_closed(real_limiter, state, expiry):
    limiter, actor = real_limiter(), identity()
    key = limiter.key(actor.organization.id, actor.application.id)
    redis_client.set(key, state, ex=expiry)
    with pytest.raises(APIError) as exc:
        limiter.check(actor)
    assert exc.value.status == 503


@pytest.mark.parametrize("result", [None, [], [1, 0], [True, 0, 1000], [2, 0, 1000],
    [1, -1, 1000], [1, 2, 1000], [1, 0, -1], [1, 0, 60001], [0, 1, 1000], [1, "0", 1000]])
def test_malformed_redis_reply_fails_closed(result):
    client = SimpleNamespace(eval=lambda *args: result)
    with pytest.raises(APIError) as exc:
        GatewayRateLimiter(client, 2, 60, "test-rate").check(identity())
    assert exc.value.status == 503


@pytest.mark.parametrize("error", [ConnectionError("private-redis-url"), ResponseError("private-command"), RuntimeError("private-error")])
def test_dependency_failure_is_sanitized(error):
    def broken(*args):
        raise error
    limiter = GatewayRateLimiter(SimpleNamespace(eval=broken), 2, 60, "test-rate")
    with pytest.raises(APIError) as exc:
        limiter.check(identity())
    assert exc.value.status == 503 and "private" not in exc.value.message


def test_endpoint_quota_rejection_never_scans_or_writes(client, db, monkeypatch, real_limiter):
    key = issue_key(client)
    limiter = real_limiter(limit=1)
    app.dependency_overrides[get_gateway_limiter] = lambda: limiter
    headers = {"Authorization": "Bearer " + key["key"]}
    first = client.post("/api/v1/gateway/scan", json={"input": "Hello"}, headers=headers)
    assert first.status_code == 200, first.text
    assert first.headers["X-RateLimit-Remaining"] == "0"
    before = set(db.scalars(select(SecurityEvent.id)))

    def forbidden(*args):
        pytest.fail("Quota rejection reached detection")
    monkeypatch.setattr(gateway, "scan", forbidden)
    response = client.post("/api/v1/gateway/scan", json={"input": "private-prompt"}, headers={
        **headers, "X-Application-ID": str(uuid4()), "X-Forwarded-For": "192.0.2.10"})
    assert response.status_code == 429 and response.headers["Retry-After"].isdigit()
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["error"]["code"] == "rate_limited"
    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]
    assert "private-prompt" not in response.text and key["key"] not in response.text
    assert set(db.scalars(select(SecurityEvent.id))) == before


def test_rotating_api_keys_cannot_bypass_application_quota(client, real_limiter):
    key = issue_key(client)
    second = client.post("/api/v1/api-keys", json={"organization_id": key["organization_id"],
        "application_id": key["application_id"]}).json()
    app.dependency_overrides[get_gateway_limiter] = lambda: real_limiter(limit=1)
    for secret, status in ((key["key"], 200), (second["key"], 429)):
        response = client.post("/api/v1/gateway/scan", json={"input": "Hello"},
            headers={"Authorization": "Bearer " + secret})
        assert response.status_code == status, response.text


def test_invalid_credentials_and_bodies_do_not_consume_quota(client):
    key = issue_key(client)
    class ForbiddenLimiter:
        def check(self, actor):
            pytest.fail("Invalid request consumed quota")
    app.dependency_overrides[get_gateway_limiter] = lambda: ForbiddenLimiter()
    assert client.post("/api/v1/gateway/scan", json={"input": "Hello"}).status_code == 401
    assert client.post("/api/v1/gateway/scan", json={"input": ""},
        headers={"Authorization": "Bearer " + key["key"]}).status_code == 422


def test_redis_outage_returns_503_before_detection(client, monkeypatch):
    key = issue_key(client)
    def broken(*args):
        raise ConnectionError("private-password")
    limiter = GatewayRateLimiter(SimpleNamespace(eval=broken), 1, 60, "test-rate")
    app.dependency_overrides[get_gateway_limiter] = lambda: limiter
    monkeypatch.setattr(gateway, "scan", lambda *args: pytest.fail("Redis outage reached scanner"))
    response = client.post("/api/v1/gateway/scan", json={"input": "Hello"},
        headers={"Authorization": "Bearer " + key["key"]})
    assert response.status_code == 503 and "private" not in response.text
    assert response.json()["error"]["code"] == "service_unavailable"


def test_downstream_failure_does_not_refund_quota(client, monkeypatch, real_limiter):
    key = issue_key(client)
    limiter = real_limiter(limit=1)
    app.dependency_overrides[get_gateway_limiter] = lambda: limiter
    original = gateway.scan

    def broken(*args):
        raise RuntimeError("private-failure")

    monkeypatch.setattr(gateway, "scan", broken)
    request_headers = {"Authorization": "Bearer " + key["key"]}
    assert client.post("/api/v1/gateway/scan", json={"input": "Hello"}, headers=request_headers).status_code == 503
    monkeypatch.setattr(gateway, "scan", original)
    assert client.post("/api/v1/gateway/scan", json={"input": "Hello"}, headers=request_headers).status_code == 429


@pytest.mark.parametrize("field,value", [
    ("gateway_rate_limit_requests", 0), ("gateway_rate_limit_requests", 1_000_001),
    ("gateway_rate_limit_window_seconds", 0), ("gateway_rate_limit_window_seconds", 3601),
    ("gateway_rate_limit_prefix", "unsafe prefix"),
])
def test_invalid_configuration_is_rejected(field, value):
    with pytest.raises(ValidationError):
        Settings(postgres_password="test", _env_file=None, **{field: value})
