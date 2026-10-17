from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import select, text

from app.api.management import Admin, Cursor, DB, Limit, paginate
from app.core.auth import require_membership
from app.core.clerk import verified_emails
from app.core.errors import APIError
from app.models import Invitation, Membership, Organization, User

router = APIRouter(prefix="/api/v1", tags=["identity"])


class InviteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    role: Literal["admin", "developer"] = "developer"


class InviteAccept(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]+$")


class RoleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["admin", "developer"]


def invitation_read(invite):
    return dict(id=invite.id, organization_id=invite.organization_id, email=invite.email,
                role=invite.role, expires_at=invite.expires_at, accepted_at=invite.accepted_at,
                revoked_at=invite.revoked_at, created_at=invite.created_at)


def lock_management_access(session, user, organization_id):
    require_membership(session, user, organization_id, manage=True)
    session.execute(text("SET LOCAL lock_timeout = '5s'"))
    session.scalar(select(Organization).where(Organization.id == organization_id)
                   .with_for_update().execution_options(populate_existing=True))
    # Recheck after waiting: a preceding writer may have removed this admin.
    require_membership(session, user, organization_id, manage=True)


@router.get("/me")
def me(session: DB, user: Admin):
    rows = session.execute(select(Membership, Organization).join(Organization).where(
        Membership.user_id == user.id, Organization.status == "active",
        Membership.role.in_(["owner", "admin", "developer"]))).all()
    return {"id": user.id, "organizations": [
        {"id": organization.id, "name": organization.name, "role": membership.role}
        for membership, organization in rows]}


@router.post("/organizations/{organization_id}/invitations", status_code=201)
def invite(organization_id: UUID, body: InviteCreate, session: DB, user: Admin):
    lock_management_access(session, user, organization_id)
    token = secrets.token_urlsafe(32)
    row = Invitation(organization_id=organization_id, email=str(body.email).casefold(), role=body.role,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7), created_by_user_id=user.id)
    session.add(row)
    session.flush()
    return {**invitation_read(row), "token": token}


@router.get("/organizations/{organization_id}/invitations")
def invitations(organization_id: UUID, session: DB, user: Admin, limit: Limit = 50, cursor: Cursor = None):
    require_membership(session, user, organization_id, manage=True)
    page = paginate(session, select(Invitation).where(Invitation.organization_id == organization_id),
                    Invitation, limit, cursor, f"invitations:{organization_id}")
    return {"items": [invitation_read(row) for row in page["items"]], "next_cursor": page["next_cursor"]}


@router.post("/organizations/{organization_id}/invitations/{invitation_id}/revoke")
def revoke_invitation(organization_id: UUID, invitation_id: UUID, session: DB, user: Admin):
    lock_management_access(session, user, organization_id)
    row = session.scalar(select(Invitation).where(Invitation.id == invitation_id,
        Invitation.organization_id == organization_id).with_for_update())
    if row is None:
        raise APIError(404, "not_found", "Invitation not found.")
    if row.accepted_at is not None:
        raise APIError(409, "conflict", "Invitation has already been accepted.")
    if row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        session.flush()
    return invitation_read(row)


@router.post("/invitations/accept")
def accept_invitation(body: InviteAccept, request: Request, session: DB, user: Admin):
    identity = getattr(request.state, "identity", None)
    if identity is None:
        raise APIError(403, "forbidden", "A verified provider identity is required.")
    # Fetch verified provider email before taking a database lock.
    emails = verified_emails(identity)
    session.execute(text("SET LOCAL lock_timeout = '5s'"))
    row = session.scalar(select(Invitation).where(
        Invitation.token_hash == hashlib.sha256(body.token.encode()).hexdigest()))
    if row is None:
        raise APIError(404, "not_found", "Invitation is unavailable.")
    organization = session.scalar(select(Organization).where(Organization.id == row.organization_id)
        .with_for_update().execution_options(populate_existing=True))
    row = session.scalar(select(Invitation).where(Invitation.id == row.id)
        .with_for_update().execution_options(populate_existing=True))
    now = datetime.now(timezone.utc)
    if row is None or row.revoked_at is not None or row.accepted_at is not None or row.expires_at <= now:
        raise APIError(404, "not_found", "Invitation is unavailable.")
    if organization is None or organization.status != "active" or row.email not in emails:
        raise APIError(403, "forbidden", "Invitation does not match the verified identity.")
    creator = session.get(User, row.created_by_user_id)
    if creator is None or creator.status != "active":
        raise APIError(403, "forbidden", "Invitation issuer is no longer authorized.")
    require_membership(session, creator, row.organization_id, manage=True)
    existing = session.scalar(select(Membership).where(Membership.user_id == user.id,
                                                       Membership.organization_id == row.organization_id))
    if existing is not None:
        raise APIError(409, "conflict", "User is already a member; invitations cannot change roles.")
    session.add(Membership(user_id=user.id, organization_id=row.organization_id, role=row.role))
    row.accepted_at, row.accepted_by_user_id = now, user.id
    session.flush()
    return {"organization_id": row.organization_id, "role": row.role}


@router.get("/organizations/{organization_id}/memberships")
def memberships(organization_id: UUID, session: DB, user: Admin, limit: Limit = 50, cursor: Cursor = None):
    require_membership(session, user, organization_id)
    page = paginate(session, select(Membership).where(Membership.organization_id == organization_id),
                    Membership, limit, cursor, f"memberships:{organization_id}")
    return {"items": [{"id": row.id, "user_id": row.user_id, "role": row.role} for row in page["items"]],
            "next_cursor": page["next_cursor"]}


def editable_membership(session, user, organization_id, membership_id):
    lock_management_access(session, user, organization_id)
    row = session.scalar(select(Membership).where(Membership.id == membership_id,
        Membership.organization_id == organization_id).with_for_update())
    if row is None:
        raise APIError(404, "not_found", "Membership not found.")
    if row.role == "owner":
        raise APIError(403, "forbidden", "Owner memberships cannot be changed through this endpoint.")
    return row


@router.patch("/organizations/{organization_id}/memberships/{membership_id}")
def update_member(organization_id: UUID, membership_id: UUID, body: RoleUpdate, session: DB, user: Admin):
    row = editable_membership(session, user, organization_id, membership_id)
    row.role = body.role
    session.flush()
    return {"id": row.id, "user_id": row.user_id, "role": row.role}


@router.delete("/organizations/{organization_id}/memberships/{membership_id}", status_code=204)
def remove_member(organization_id: UUID, membership_id: UUID, session: DB, user: Admin):
    row = editable_membership(session, user, organization_id, membership_id)
    session.delete(row)
    session.flush()
