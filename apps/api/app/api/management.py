import base64
import binascii
import json
import secrets
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import get_admin, hash_key, require_membership
from app.core.database import get_session
from app.core.errors import APIError
from app.models import APIKey, Application, Membership, Organization, User
from app.schemas.management import (
    ApplicationCreate, ApplicationPage, ApplicationRead, KeyCreate, KeyCreated,
    KeyPage, KeyRevoked, NamedCreate, OrganizationPage, OrganizationRead,
)

router = APIRouter(prefix="/api/v1", tags=["management"])
DB = Annotated[Session, Depends(get_session)]
Admin = Annotated[User, Depends(get_admin)]
Limit = Annotated[int, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=1024)]


def paginate(session, statement, model, limit, cursor, context):
    if cursor:
        try:
            payload = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
            if not isinstance(payload, dict) or not all(
                isinstance(payload.get(field), str) for field in ("context", "created_at", "id")
            ):
                raise ValueError("Invalid cursor structure")
            if payload["context"] != context:
                raise ValueError("Wrong cursor context")
            created_at = datetime.fromisoformat(payload["created_at"])
            if created_at.tzinfo is None:
                raise ValueError("Timezone required")
            item_id = UUID(payload["id"])
        except (ValueError, TypeError, KeyError, binascii.Error):
            raise APIError(422, "validation_error", "Invalid pagination cursor.") from None
        statement = statement.where(tuple_(model.created_at, model.id) < tuple_(created_at, item_id))
    rows = list(session.scalars(statement.order_by(model.created_at.desc(), model.id.desc()).limit(limit + 1)))
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = base64.urlsafe_b64encode(json.dumps({
            "context": context, "created_at": last.created_at.isoformat(), "id": str(last.id)
        }).encode()).decode()
    return {"items": rows[:limit], "next_cursor": next_cursor}


def application_for(session, user, application_id, manage=False):
    application = session.get(Application, application_id)
    if application is None:
        raise APIError(404, "not_found", "Application not found.")
    require_membership(session, user, application.organization_id, manage)
    return application


@router.post("/organizations", response_model=OrganizationRead, status_code=201)
def create_organization(body: NamedCreate, session: DB, user: Admin):
    organization = Organization(name=body.name)
    session.add(organization)
    session.flush()
    session.add(Membership(organization_id=organization.id, user_id=user.id, role="owner"))
    session.flush()
    return organization


@router.get("/organizations", response_model=OrganizationPage)
def list_organizations(session: DB, user: Admin, limit: Limit = 50, cursor: Cursor = None):
    statement = select(Organization).join(Membership).where(Membership.user_id == user.id)
    return paginate(session, statement, Organization, limit, cursor, f"organizations:{user.id}")


@router.get("/organizations/{organization_id}", response_model=OrganizationRead)
def get_organization(organization_id: UUID, session: DB, user: Admin):
    return require_membership(session, user, organization_id)


@router.post("/applications", response_model=ApplicationRead, status_code=201)
def create_application(body: ApplicationCreate, session: DB, user: Admin):
    require_membership(session, user, body.organization_id, manage=True)
    application = Application(organization_id=body.organization_id, name=body.name)
    session.add(application)
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        if getattr(exc.orig, "sqlstate", None) == "23505":
            raise APIError(409, "conflict", "Application name already exists in this organization.") from None
        raise
    return application


@router.get("/applications/{application_id}", response_model=ApplicationRead)
def get_application(application_id: UUID, session: DB, user: Admin):
    return application_for(session, user, application_id)


@router.get("/organizations/{organization_id}/applications", response_model=ApplicationPage)
def list_applications(organization_id: UUID, session: DB, user: Admin,
                      limit: Limit = 50, cursor: Cursor = None):
    require_membership(session, user, organization_id)
    statement = select(Application).where(Application.organization_id == organization_id)
    return paginate(session, statement, Application, limit, cursor, f"applications:{organization_id}")


@router.post("/api-keys", response_model=KeyCreated, status_code=201)
def create_key(body: KeyCreate, session: DB, user: Admin):
    require_membership(session, user, body.organization_id, manage=True)
    application = session.scalar(select(Application).where(
        Application.id == body.application_id, Application.organization_id == body.organization_id))
    if application is None:
        raise APIError(404, "not_found", "Application not found.")
    if application.status != "active":
        raise APIError(403, "forbidden", "Application is inactive.")
    for _ in range(3):
        prefix = f"inj_live_{secrets.token_hex(8)}"
        secret = f"{prefix}_{secrets.token_urlsafe(32)}"
        record = APIKey(organization_id=body.organization_id, application_id=body.application_id,
                        key_prefix=prefix, key_hash=hash_key(secret), scopes=body.scopes,
                        expires_at=body.expires_at)
        try:
            with session.begin_nested():
                session.add(record)
                session.flush()
            return {**{field: getattr(record, field) for field in (
                "id", "organization_id", "application_id", "key_prefix", "scopes",
                "expires_at", "revoked_at", "created_at")}, "key": secret}
        except IntegrityError as exc:
            if getattr(getattr(exc.orig, "diag", None), "constraint_name", None) != "uq_api_key_prefix":
                raise
    raise APIError(503, "service_unavailable", "Unable to allocate API key.")


@router.get("/applications/{application_id}/api-keys", response_model=KeyPage)
def list_keys(application_id: UUID, session: DB, user: Admin,
              limit: Limit = 50, cursor: Cursor = None):
    application = application_for(session, user, application_id, manage=True)
    statement = select(APIKey).where(APIKey.application_id == application_id,
                                     APIKey.organization_id == application.organization_id)
    return paginate(session, statement, APIKey, limit, cursor, f"keys:{application_id}")


@router.post("/api-keys/{api_key_id}/revoke", response_model=KeyRevoked)
def revoke_key(api_key_id: UUID, session: DB, user: Admin):
    # Serialize concurrent revocations so every caller gets the original timestamp.
    record = session.scalar(select(APIKey).where(APIKey.id == api_key_id).with_for_update())
    if record is None:
        raise APIError(404, "not_found", "API key not found.")
    require_membership(session, user, record.organization_id, manage=True)
    if record.revoked_at is None:
        record.revoked_at = datetime.now(timezone.utc)
        session.flush()
    return record
