from datetime import datetime, timedelta, timezone

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.auth import get_admin, hash_key, require_gateway_scope
from app.core.config import settings
from app.core.database import get_session
from app.main import app
from app.models import APIKey, Application, Membership, Organization, User


def setup_application(client, name="Assistant"):
    response = client.post("/api/v1/organizations", json={"name": "Acme"})
    assert response.status_code == 201, response.text
    organization_id = response.json()["id"]
    response = client.post("/api/v1/applications", json={"organization_id": organization_id, "name": name})
    assert response.status_code == 201, response.text
    return organization_id, response.json()["id"]


def issue_key(client):
    organization_id, application_id = setup_application(client)
    response = client.post("/api/v1/api-keys", json={
        "organization_id": organization_id, "application_id": application_id, "scopes": ["gateway:scan"]})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def gateway(client):
    async def probe(identity=Depends(require_gateway_scope())):
        return {"organization_id": str(identity.organization.id), "application_id": str(identity.application.id)}
    original_routes = list(app.router.routes)
    app.add_api_route("/_test/gateway", probe, methods=["POST"])
    yield client
    app.router.routes[:] = original_routes


def test_organization_owner_and_trimmed_names(client, db):
    organization_id, application_id = setup_application(client, "  Support  ")
    membership = db.scalar(select(Membership).where(Membership.organization_id == organization_id))
    assert membership.user_id == client.admin_user.id and membership.role == "owner"
    assert client.get(f"/api/v1/applications/{application_id}").json()["name"] == "Support"
    assert client.get(f"/api/v1/organizations/{organization_id}").status_code == 200


def test_duplicate_application_is_tenant_scoped(client):
    organization_id, _ = setup_application(client)
    body = {"organization_id": organization_id, "name": "Assistant"}
    assert client.post("/api/v1/applications", json=body).status_code == 409
    assert client.post("/api/v1/applications", json={**body, "name": "assistant"}).status_code == 201
    setup_application(client)


@pytest.mark.parametrize("name", ["", "   ", "x" * 151])
def test_invalid_name(client, name):
    assert client.post("/api/v1/organizations", json={"name": name}).status_code == 422


def test_foreign_tenant_access_and_key_mismatch(client, db):
    own_org, own_app = setup_application(client)
    foreign_org = Organization(name="Foreign")
    db.add(foreign_org)
    db.flush()
    foreign_app = Application(organization_id=foreign_org.id, name="Foreign")
    db.add(foreign_app)
    db.flush()
    for path in (f"organizations/{foreign_org.id}", f"applications/{foreign_app.id}",
                 f"organizations/{foreign_org.id}/applications", f"applications/{foreign_app.id}/api-keys"):
        assert client.get("/api/v1/" + path).status_code == 404
    assert client.post("/api/v1/applications", json={"organization_id": str(foreign_org.id), "name": "X"}).status_code == 404
    assert client.post("/api/v1/api-keys", json={"organization_id": own_org, "application_id": str(foreign_app.id)}).status_code == 404
    assert client.post("/api/v1/api-keys", json={"organization_id": str(foreign_org.id), "application_id": own_app}).status_code == 404
    assert [item["id"] for item in client.get("/api/v1/organizations").json()["items"]] == [own_org]


def test_roles_and_foreign_revocation(client, db):
    key = issue_key(client)
    organization_id = key["organization_id"]
    membership = db.scalar(select(Membership).where(Membership.organization_id == organization_id))
    membership.role = "developer"
    db.flush()
    assert client.get(f"/api/v1/applications/{key['application_id']}").status_code == 200
    assert client.post("/api/v1/applications", json={"organization_id": organization_id, "name": "Other"}).status_code == 403
    assert client.post("/api/v1/api-keys", json={"organization_id": organization_id, "application_id": key["application_id"]}).status_code == 403
    assert client.get(f"/api/v1/applications/{key['application_id']}/api-keys").status_code == 403
    assert client.post(f"/api/v1/api-keys/{key['id']}/revoke").status_code == 403
    other = User(identity_subject="outsider")
    db.add(other)
    db.flush()
    app.dependency_overrides[get_admin] = lambda: other
    assert client.post(f"/api/v1/api-keys/{key['id']}/revoke").status_code == 404


def test_key_storage_disclosure_and_idempotent_revocation(client, db):
    key = issue_key(client)
    record = db.get(APIKey, key["id"])
    assert record.key_hash == hash_key(key["key"])
    assert key["key"] != record.key_hash and len(record.key_prefix) == 25
    metadata = client.get(f"/api/v1/applications/{key['application_id']}/api-keys").json()["items"][0]
    assert "key" not in metadata and "key_hash" not in metadata
    first = client.post(f"/api/v1/api-keys/{key['id']}/revoke")
    second = client.post(f"/api/v1/api-keys/{key['id']}/revoke")
    assert first.status_code == 200 and first.json() == second.json()


@pytest.mark.parametrize("overrides", [
    {"scopes": ["keys:manage"]}, {"scopes": []}, {"scopes": ["gateway:scan", "gateway:scan"]},
    {"expires_at": "2020-01-01T00:00:00Z"}, {"expires_at": "2099-01-01T00:00:00"},
])
def test_key_validation(client, overrides):
    organization_id, application_id = setup_application(client)
    assert client.post("/api/v1/api-keys", json={"organization_id": organization_id,
                       "application_id": application_id, **overrides}).status_code == 422


def test_pagination_validation_and_tenant_binding(client):
    ids = [client.post("/api/v1/organizations", json={"name": str(i)}).json()["id"] for i in range(3)]
    first = client.get("/api/v1/organizations?limit=2").json()
    second = client.get("/api/v1/organizations", params={"limit": 2, "cursor": first["next_cursor"]}).json()
    assert len(first["items"]) == 2 and len(second["items"]) == 1 and second["next_cursor"] is None
    assert {i["id"] for i in first["items"] + second["items"]} == set(ids)
    for query in ({"limit": 0}, {"limit": 101}, {"cursor": "bad"}):
        assert client.get("/api/v1/organizations", params=query).status_code == 422
    assert client.get(f"/api/v1/organizations/{ids[0]}/applications", params={"cursor": first["next_cursor"]}).status_code == 422


def test_gateway_identity_and_credential_failures(gateway, db):
    key = issue_key(gateway)
    headers = {"Authorization": "Bearer " + key["key"]}
    result = gateway.post("/_test/gateway", headers=headers)
    assert result.status_code == 200
    assert result.json() == {"organization_id": key["organization_id"], "application_id": key["application_id"]}
    for authorization in (None, "Basic abc", "Bearer invalid", "Bearer " + key["key"][:-1] + "."):
        assert gateway.post("/_test/gateway", headers={"Authorization": authorization} if authorization else {}).status_code == 401
    record = db.get(APIKey, key["id"])
    record.revoked_at = datetime.now(timezone.utc)
    db.commit()
    wrong_secret = key["key"][:26] + "a" * 43
    assert gateway.post("/_test/gateway", headers={"Authorization": "Bearer " + wrong_secret}).json()["error"]["code"] == "invalid_api_key"
    assert gateway.post("/_test/gateway", headers=headers).json()["error"]["code"] == "revoked_api_key"
    record.revoked_at = None
    record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert gateway.post("/_test/gateway", headers=headers).json()["error"]["code"] == "expired_api_key"
    record.expires_at = None
    record.scopes = []
    db.commit()
    assert gateway.post("/_test/gateway", headers=headers).status_code == 403


@pytest.mark.parametrize("model", [Organization, Application])
def test_inactive_tenant_or_application(gateway, db, model):
    key = issue_key(gateway)
    record_id = key["organization_id"] if model is Organization else key["application_id"]
    db.get(model, record_id).status = "disabled"
    db.flush()
    assert gateway.post("/_test/gateway", headers={"Authorization": "Bearer " + key["key"]}).status_code == 401


def test_missing_pepper_fails_closed(client, monkeypatch):
    organization_id, application_id = setup_application(client)
    monkeypatch.setattr(settings, "api_key_pepper", None)
    assert client.post("/api/v1/api-keys", json={"organization_id": organization_id, "application_id": application_id}).status_code == 503


def test_management_adapter_is_disabled_by_default(db, monkeypatch):
    app.dependency_overrides[get_session] = lambda: db
    monkeypatch.setattr(settings, "dev_admin_enabled", False)
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/organizations", json={"name": "Acme"})
            assert response.status_code == 401
            assert response.headers["www-authenticate"] == "Bearer"
    finally:
        app.dependency_overrides.clear()


def test_local_adapter_requires_token_loopback_and_active_user(db, monkeypatch):
    token = "local-token-" + "t" * 32
    user = User(identity_subject="configured-admin")
    db.add(user)
    db.flush()
    for name, value in {"app_environment": "development", "dev_admin_enabled": True,
                        "dev_admin_subject": user.identity_subject, "dev_admin_token": SecretStr(token)}.items():
        monkeypatch.setattr(settings, name, value)
    app.dependency_overrides[get_session] = lambda: db
    async def loopback_app(scope, receive, send):
        if scope["type"] == "http":
            scope["client"] = ("127.0.0.1", 50000)
        await app(scope, receive, send)

    try:
        with TestClient(loopback_app) as client:
            assert client.get("/api/v1/organizations").status_code == 401
            assert client.get("/api/v1/organizations", headers={"Authorization": "Bearer wrong"}).status_code == 401
            assert client.get("/api/v1/organizations", headers={"Authorization": "Bearer " + token}).status_code == 200
            user.status = "disabled"
            db.flush()
            assert client.get("/api/v1/organizations", headers={"Authorization": "Bearer " + token}).status_code == 401
        with TestClient(app) as client:
            assert client.get("/api/v1/organizations", headers={"Authorization": "Bearer " + token}).status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_database_enforces_cross_tenant_key_ownership(client, db):
    _, application_id = setup_application(client)
    other = Organization(name="Other")
    db.add(other)
    db.flush()
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(APIKey(organization_id=other.id, application_id=application_id,
                          key_prefix="wrong", key_hash="hash", scopes=[]))
            db.flush()


def test_request_ids_and_safe_errors(client):
    response = client.get("/api/v1/organizations/not-a-uuid", headers={"X-Request-ID": "untrusted"})
    assert response.status_code == 422
    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]
    assert response.headers["x-request-id"] != "untrusted"
    assert "not-a-uuid" not in response.text
    assert client.get("/missing").json()["error"]["code"] == "not_found"


def test_structurally_invalid_cursor_is_validation_error(client):
    import base64
    import json
    for payload in ([], {"context": "x", "created_at": "x", "id": 3}):
        cursor = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        assert client.get("/api/v1/organizations", params={"cursor": cursor}).status_code == 422


def test_key_prefix_collision_retries(client, monkeypatch):
    import app.api.management as management
    first = issue_key(client)
    original = management.secrets.token_hex
    attempts = iter([first["key_prefix"][9:], original(8)])
    monkeypatch.setattr(management.secrets, "token_hex", lambda _: next(attempts))
    response = client.post("/api/v1/api-keys", json={"organization_id": first["organization_id"],
                           "application_id": first["application_id"]})
    assert response.status_code == 201
    assert response.json()["key_prefix"] != first["key_prefix"]


def test_gateway_keys_cannot_authenticate_management(gateway):
    key = issue_key(gateway)
    app.dependency_overrides.pop(get_admin)
    response = gateway.get("/api/v1/organizations", headers={"Authorization": "Bearer " + key["key"]})
    assert response.status_code == 401


def test_unknown_key_and_application_identity_cannot_be_overridden(gateway):
    key = issue_key(gateway)
    response = gateway.post("/_test/gateway", headers={"Authorization": "Bearer " + key["key"],
                            "X-Organization-ID": "foreign", "X-Application-ID": "foreign"})
    assert response.json()["application_id"] == key["application_id"]
    unknown = "inj_live_" + "0" * 16 + "_" + "a" * 43
    assert gateway.post("/_test/gateway", headers={"Authorization": "Bearer " + unknown}).status_code == 401


def test_persistent_transactions_and_safe_database_failure(migrated_engine, monkeypatch):
    import app.core.database as database
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import Session
    from uuid import uuid4

    subject = "persistence-" + uuid4().hex
    monkeypatch.setattr(database, "engine", migrated_engine)
    with Session(migrated_engine) as session, session.begin():
        user = User(identity_subject=subject)
        session.add(user)
        session.flush()
        user_id = user.id
    def admin():
        with Session(migrated_engine) as session:
            return session.get(User, user_id)
    app.dependency_overrides[get_admin] = admin
    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/organizations", json={"name": "Persistent"})
            assert response.status_code == 201
            organization_id = response.json()["id"]
            with Session(migrated_engine) as session:
                assert session.get(Organization, organization_id) is not None
                assert session.scalar(select(Membership).where(Membership.organization_id == organization_id)).user_id == user_id

            original_flush = Session.flush
            def broken_flush(session, *args, **kwargs):
                original_flush(session, *args, **kwargs)
                raise OperationalError("secret SQL", {"credential": "do-not-expose"}, Exception("private"))
            monkeypatch.setattr(Session, "flush", broken_flush)
            response = client.post("/api/v1/organizations", json={"name": "Must rollback"})
            assert response.status_code == 503
            assert "secret" not in response.text and "do-not-expose" not in response.text
            monkeypatch.setattr(Session, "flush", original_flush)
            with Session(migrated_engine) as session:
                assert session.scalar(select(Organization).where(Organization.name == "Must rollback")) is None
    finally:
        app.dependency_overrides.clear()
