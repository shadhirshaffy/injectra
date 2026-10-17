from datetime import datetime, timedelta, timezone
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from time import time
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import httpx
from fastapi import Request
from pydantic import SecretStr, ValidationError
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import clerk
from app.core.auth import get_admin
from app.core.config import Settings, settings
from app.core.errors import APIError
from app.main import app
from app.models import Invitation, Membership, Organization, User
from test_management import setup_application


@pytest.fixture(scope="module")
def signing_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    return private, {**key, "kid": "test-key", "alg": "RS256", "use": "sig"}


@pytest.fixture
def clerk_client(client, monkeypatch, signing_pair):
    private, public = signing_pair
    for name, value in {"management_auth_provider": "clerk", "clerk_issuer": "https://identity.example.test",
        "clerk_authorized_parties": ["https://app.example.test"], "clerk_secret_key": SecretStr("sk_test_fake"),
        "clerk_audience": None, "dev_admin_enabled": False}.items():
        monkeypatch.setattr(settings, name, value)
    monkeypatch.setattr(clerk, "signing_keys", clerk.SigningKeys())
    state = {"status": "active", "emails": ["invited@example.com"], "jwks": [public], "fail": False}

    def remote(url, authenticated=False):
        if state["fail"]:
            raise APIError(503, "service_unavailable", "Identity verification unavailable.")
        if url.endswith("/.well-known/jwks.json"):
            assert not authenticated and url.startswith(settings.clerk_issuer)
            return {"keys": state["jwks"]}
        if "/sessions/" in url:
            assert authenticated
            return {"id": "sess_testOne", "user_id": "user_testOne", "status": state["status"]}
        assert url == "https://api.clerk.com/v1/users/user_testOne" and authenticated
        return {"id": "user_testOne", "email_addresses": [
            {"email_address": email, "verification": {"status": "verified"}} for email in state["emails"]]}

    monkeypatch.setattr(clerk, "remote_json", remote)
    original = app.dependency_overrides.pop(get_admin)

    def token(**changes):
        now = int(time())
        claims = {"iss": settings.clerk_issuer, "sub": "user_testOne", "sid": "sess_testOne",
                  "iat": now, "nbf": now, "exp": now + 60, "azp": "https://app.example.test"}
        claims.update(changes)
        return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "test-key"})

    try:
        yield client, token, state
    finally:
        app.dependency_overrides[get_admin] = original


def auth(token):
    return {"Authorization": "Bearer " + token}


def test_verified_identity_is_provisioned_without_memberships(clerk_client, db):
    client, token, _ = clerk_client
    response = client.get("/api/v1/me", headers=auth(token()))
    assert response.status_code == 200, response.text
    assert response.json()["organizations"] == []
    user = db.get(User, UUID(response.json()["id"]))
    assert user.identity_issuer == settings.clerk_issuer and user.identity_subject == "user_testOne"
    assert client.get("/api/v1/me", headers=auth(token())).json()["id"] == str(user.id)
    assert len(list(db.scalars(select(User).where(User.identity_issuer == settings.clerk_issuer)))) == 1


@pytest.mark.parametrize("changes", [
    {"iss": "https://foreign.example.test"}, {"azp": "https://evil.example.test"},
    {"exp": 1}, {"nbf": int(time()) + 1000}, {"iat": int(time()) + 1000},
    {"exp": int(time()) + 10000}, {"sid": "machine-token"}, {"sub": "not-a-user"},
    {"sid": None}, {"sts": "pending"}, {"iat": True},
])
def test_invalid_claims_fail_closed(clerk_client, changes):
    client, token, _ = clerk_client
    response = client.get("/api/v1/me", headers=auth(token(**changes)))
    assert response.status_code == 401, response.text
    assert response.json()["error"]["code"] == "unauthenticated"
    assert "WWW-Authenticate" in response.headers


def test_origin_and_audience_are_enforced(clerk_client, monkeypatch):
    client, token, _ = clerk_client
    assert client.get("/api/v1/me", headers={**auth(token()), "Origin": "https://evil.example.test"}).status_code == 401
    monkeypatch.setattr(settings, "clerk_audience", "injectra-api")
    assert client.get("/api/v1/me", headers=auth(token())).status_code == 401
    assert client.get("/api/v1/me", headers=auth(token(aud="injectra-api"))).status_code == 200


def test_forged_and_missing_tokens(clerk_client):
    client, token, _ = clerk_client
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/v1/me", headers=auth("inj_live_not-a-session")).status_code == 401
    assert client.get("/api/v1/me", headers=auth(token()[:-8] + "forgedxx")).status_code == 401
    forged = jwt.encode({"sub": "user_testOne"}, "attacker-key" * 4, algorithm="HS256", headers={"kid": "test-key"})
    assert client.get("/api/v1/me", headers=auth(forged)).status_code == 401


def test_remote_failure_and_revoked_session(clerk_client):
    client, token, state = clerk_client
    state["fail"] = True
    assert client.get("/api/v1/me", headers=auth(token())).status_code == 503
    state["fail"] = False
    assert client.get("/api/v1/me", headers=auth(token())).status_code == 200
    state["status"] = "revoked"
    response = client.post("/api/v1/organizations", json={"name": "Forbidden"}, headers=auth(token()))
    assert response.status_code == 401
    state["fail"] = True
    assert client.post("/api/v1/organizations", json={"name": "Forbidden"}, headers=auth(token())).status_code == 503


def test_local_suspension_takes_effect_immediately(clerk_client, db):
    client, token, _ = clerk_client
    user_id = client.get("/api/v1/me", headers=auth(token())).json()["id"]
    db.get(User, UUID(user_id)).status = "disabled"
    db.flush()
    assert client.get("/api/v1/me", headers=auth(token())).status_code == 401


def test_no_automatic_linking_to_development_identity(clerk_client, db):
    client, token, _ = clerk_client
    local_user = User(identity_subject="user_testOne")
    db.add(local_user)
    db.flush()
    response = client.get("/api/v1/me", headers=auth(token()))
    assert response.status_code == 200 and response.json()["id"] != str(local_user.id)


def test_clerk_user_cannot_access_existing_tenant(clerk_client, db):
    client, token, _ = clerk_client
    organization = Organization(name="Foreign")
    db.add(organization)
    db.flush()
    assert client.get(f"/api/v1/organizations/{organization.id}", headers=auth(
        token(org_id=str(organization.id), org_role="org:admin"))).status_code == 404


def test_key_rotation_and_cache_expiry(clerk_client):
    client, token, state = clerk_client
    assert client.get("/api/v1/me", headers=auth(token())).status_code == 200
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(other.public_key()))
    state["jwks"] = [{**public, "kid": "test-key", "alg": "RS256"}]
    claims = jwt.decode(token(), options={"verify_signature": False})
    rotated = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "test-key"})
    clerk.signing_keys.refreshed -= 10
    assert client.get("/api/v1/me", headers=auth(rotated)).status_code == 200
    clerk.signing_keys.expires = 0
    state["fail"] = True
    assert client.get("/api/v1/me", headers=auth(rotated)).status_code == 503


def test_configuration_rejects_unsafe_production_settings():
    base = {"postgres_password": "test", "_env_file": None}
    with pytest.raises(ValidationError):
        Settings(**base, app_environment="production", dev_admin_enabled=True)
    with pytest.raises(ValidationError):
        Settings(**base, management_auth_provider="clerk")
    with pytest.raises(ValidationError):
        Settings(**base, management_auth_provider="clerk", clerk_issuer="http://untrusted", clerk_secret_key="x",
                 clerk_authorized_parties=["https://app.example.test"])


def test_invitation_email_binding_replay_and_owner_protection(client, db, monkeypatch):
    org_id, _ = setup_application(client)
    owner = client.admin_user
    url = f"/api/v1/organizations/{org_id}"
    created = client.post(url + "/invitations", json={"email": "invited@example.com"}).json()
    assert "token_hash" not in created and len(created["token"]) == 43
    listed = client.get(url + "/invitations").json()
    assert "token" not in listed["items"][0]
    invited = User(identity_issuer="https://identity.example.test", identity_subject="user_invited")
    db.add(invited)
    db.flush()
    db.commit()
    identity = clerk.VerifiedIdentity(invited.identity_issuer, invited.identity_subject, "sess_invited")

    def invited_user(request: Request):
        request.state.identity = identity
        return invited

    app.dependency_overrides[get_admin] = invited_user
    monkeypatch.setattr("app.api.identity.verified_emails", lambda _: {"wrong@example.com"})
    assert client.post("/api/v1/invitations/accept", json={"token": created["token"]}).status_code == 403
    monkeypatch.setattr("app.api.identity.verified_emails", lambda _: {"invited@example.com"})
    assert client.post("/api/v1/invitations/accept", json={"token": created["token"]}).status_code == 200
    assert client.post("/api/v1/invitations/accept", json={"token": created["token"]}).status_code == 404
    assert client.get("/api/v1/me").json()["organizations"][0]["role"] == "developer"
    assert client.post(url + "/invitations", json={"email": "other@example.com"}).status_code == 403
    app.dependency_overrides[get_admin] = lambda: owner
    another = client.post(url + "/invitations", json={"email": "invited@example.com", "role": "admin"}).json()
    app.dependency_overrides[get_admin] = invited_user
    assert client.post("/api/v1/invitations/accept", json={"token": another["token"]}).status_code == 409
    assert client.get("/api/v1/me").json()["organizations"][0]["role"] == "developer"
    app.dependency_overrides[get_admin] = lambda: owner
    owner_membership = db.scalar(select(Membership).where(Membership.user_id == owner.id,
                                                         Membership.organization_id == UUID(org_id)))
    assert client.delete(url + f"/memberships/{owner_membership.id}").status_code == 403
    member = db.scalar(select(Membership).where(Membership.user_id == invited.id))
    assert client.patch(url + f"/memberships/{member.id}", json={"role": "admin"}).status_code == 200
    assert client.patch(url + f"/memberships/{member.id}", json={"role": "owner"}).status_code == 422
    assert client.delete(url + f"/memberships/{member.id}").status_code == 204


@pytest.mark.parametrize("state", ["expired", "revoked"])
def test_unavailable_invitation(client, db, monkeypatch, state):
    org_id, _ = setup_application(client)
    created = client.post(f"/api/v1/organizations/{org_id}/invitations", json={"email": "invited@example.com"}).json()
    row = db.get(Invitation, UUID(created["id"]))
    if state == "expired":
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    else:
        row.revoked_at = datetime.now(timezone.utc)
    db.flush()
    user = client.admin_user

    def current_user(request: Request):
        request.state.identity = clerk.VerifiedIdentity("https://identity.example.test", "user_testOne", "sess_testOne")
        return user

    app.dependency_overrides[get_admin] = current_user
    monkeypatch.setattr("app.api.identity.verified_emails", lambda _: {"invited@example.com"})
    assert client.post("/api/v1/invitations/accept", json={"token": created["token"]}).status_code == 404


def test_provider_io_is_bounded_and_never_follows_redirects(monkeypatch):
    monkeypatch.setattr(settings, "clerk_secret_key", SecretStr("sk_test_fake"))
    seen = []
    response = httpx.Response(200, json={"status": "active"})

    class Client:
        def __init__(self, **kwargs):
            assert kwargs == {"timeout": 3.0, "follow_redirects": False, "trust_env": False}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def get(self, url, headers):
            seen.append((url, headers))
            return response

    monkeypatch.setattr(clerk.httpx, "Client", Client)
    assert clerk.remote_json("https://api.clerk.com/v1/sessions/sess_test", True)["status"] == "active"
    assert seen[-1][1]["Authorization"] == "Bearer sk_test_fake"
    clerk.remote_json("https://identity.example.test/.well-known/jwks.json")
    assert "Authorization" not in seen[-1][1]
    response = httpx.Response(302, headers={"location": "https://untrusted.example"})
    with pytest.raises(APIError) as exc:
        clerk.remote_json("https://api.clerk.com/v1/sessions/sess_test", True)
    assert exc.value.status == 503
    response = httpx.Response(404)
    with pytest.raises(APIError) as exc:
        clerk.remote_json("https://api.clerk.com/v1/sessions/sess_test", True)
    assert exc.value.status == 401


def test_invalid_remote_payloads_fail_closed(monkeypatch):
    identity = clerk.VerifiedIdentity("https://identity.example.test", "user_testOne", "sess_testOne")
    monkeypatch.setattr(clerk, "remote_json", lambda *args, **kwargs: {})
    with pytest.raises(APIError) as exc:
        clerk.require_live_session(identity)
    assert exc.value.status == 503
    monkeypatch.setattr(clerk, "remote_json", lambda *args, **kwargs: {"id": "user_testOne", "email_addresses": None})
    with pytest.raises(APIError) as exc:
        clerk.verified_emails(identity)
    assert exc.value.status == 503


def test_invite_api_cannot_grant_owner_or_leak_foreign_invitations(client, db):
    org, _ = setup_application(client)
    url = f"/api/v1/organizations/{org}/invitations"
    assert client.post(url, json={"email": "invited@example.com", "role": "owner"}).status_code == 422
    foreign = Organization(name="Foreign")
    db.add(foreign)
    db.flush()
    assert client.get(f"/api/v1/organizations/{foreign.id}/invitations").status_code == 404
    assert client.post(f"/api/v1/organizations/{foreign.id}/invitations", json={"email": "invited@example.com"}).status_code == 404


def test_unknown_membership_roles_are_not_authorized(client, db):
    org, _ = setup_application(client)
    member = db.scalar(select(Membership).where(Membership.organization_id == UUID(org)))
    member.role = "unexpected-role"
    db.flush()
    db.commit()
    assert client.get(f"/api/v1/organizations/{org}").status_code == 403
    assert client.get("/api/v1/me").json()["organizations"] == []
    assert client.get("/api/v1/organizations").json()["items"] == []


def test_revocation_is_idempotent_and_hides_token_hash(client, db):
    org, _ = setup_application(client)
    url = f"/api/v1/organizations/{org}/invitations"
    created = client.post(url, json={"email": "invited@example.com"}).json()
    revoke = url + "/" + created["id"] + "/revoke"
    first = client.post(revoke)
    assert first.status_code == 200
    assert client.post(revoke).json()["revoked_at"] == first.json()["revoked_at"]
    row = db.get(Invitation, UUID(created["id"]))
    assert created["token"] != row.token_hash and row.token_hash not in client.get(url).text


def test_explicit_identity_link_preserves_memberships(client, db, monkeypatch):
    from app import cli
    # Use the test session so the operator command's transaction is isolated.
    org, _ = setup_application(client)
    user = client.admin_user
    monkeypatch.setattr(settings, "management_auth_provider", "clerk")
    monkeypatch.setattr(settings, "clerk_issuer", "https://identity.example.test")
    monkeypatch.setattr(cli, "remote_json", lambda *args, **kwargs: {"id": "user_linked"})

    class Context:
        def __enter__(self):
            return db
        def __exit__(self, *args):
            pass

    class SessionProxy:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def begin(self):
            return Context()

    # CLI uses its context-managed session; delegate methods explicitly.
    class Proxy(SessionProxy):
        def scalar(self, statement):
            return db.scalar(statement)

    monkeypatch.setattr(cli, "Session", lambda *args: Proxy())
    monkeypatch.setattr("sys.argv", ["cli", "link-clerk-user", "--user-id", str(user.id), "--subject", "user_linked"])
    cli.main()
    db.flush()
    assert user.identity_issuer == settings.clerk_issuer and user.identity_subject == "user_linked"
    assert db.scalar(select(Membership).where(Membership.organization_id == UUID(org))).user_id == user.id


def test_identity_migration_preserves_legacy_users_and_roles():
    from pathlib import Path
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, text
    from app.core.database import database_url, engine

    schema = "test_identity_migration_" + uuid4().hex
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated = create_engine(database_url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
        config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "migrations"))
        with isolated.begin() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "c815f6b23d10")
            user_id, org_id = uuid4(), uuid4()
            connection.execute(text("INSERT INTO users (id, identity_subject, status) VALUES (:id, 'legacy-subject', 'active')"), {"id": user_id})
            connection.execute(text("INSERT INTO organizations (id, name, status) VALUES (:id, 'Legacy', 'active')"), {"id": org_id})
            connection.execute(text("INSERT INTO memberships (id, organization_id, user_id, role) VALUES (:id, :org, :usr, 'member')"), {"id": uuid4(), "org": org_id, "usr": user_id})
            command.upgrade(config, "head")
            command.check(config)
            assert connection.scalar(text("SELECT identity_issuer FROM users WHERE id = :id"), {"id": user_id}) == "local-development"
            assert connection.scalar(text("SELECT role FROM memberships WHERE user_id = :id"), {"id": user_id}) == "developer"
            command.downgrade(config, "c815f6b23d10")
            assert connection.scalar(text("SELECT identity_subject FROM users WHERE id = :id"), {"id": user_id}) == "legacy-subject"
    finally:
        isolated.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


def test_concurrent_invitation_acceptance_is_single_use(migrated_engine, monkeypatch):
    import hashlib
    from app.api.identity import InviteAccept, accept_invitation
    code = secrets.token_urlsafe(32)
    with Session(migrated_engine) as session:
        owner = User(identity_subject="owner-" + uuid4().hex)
        member = User(identity_issuer="https://identity.example.test", identity_subject="user_" + uuid4().hex)
        org = Organization(name="Concurrent invitation")
        session.add_all([owner, member, org])
        session.flush()
        session.add(Membership(organization_id=org.id, user_id=owner.id, role="owner"))
        session.add(Invitation(organization_id=org.id, email="invited@example.com", role="developer",
            token_hash=hashlib.sha256(code.encode()).hexdigest(), created_by_user_id=owner.id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1)))
        member_id, org_id = member.id, org.id
        session.commit()
    monkeypatch.setattr("app.api.identity.verified_emails", lambda _: {"invited@example.com"})
    barrier = Barrier(2)

    def accept():
        with Session(migrated_engine) as session:
            user = session.get(User, member_id)
            request = Request({"type": "http", "headers": []})
            request.state.identity = clerk.VerifiedIdentity(user.identity_issuer, user.identity_subject, "sess_test")
            barrier.wait(timeout=10)
            try:
                accept_invitation(InviteAccept(token=code), request, session, user)
                session.commit()
                return 200
            except APIError as exc:
                session.rollback()
                return exc.status

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(accept) for _ in range(2)]
        assert sorted(future.result(timeout=20) for future in futures) == [200, 404]
    with Session(migrated_engine) as session:
        assert len(list(session.scalars(select(Membership).where(
            Membership.organization_id == org_id, Membership.user_id == member_id)))) == 1
