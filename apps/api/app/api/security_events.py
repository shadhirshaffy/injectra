from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import AwareDatetime
from sqlalchemy import select

from app.api.management import Admin, Cursor, DB, Limit, application_for, paginate
from app.core.auth import require_membership
from app.core.errors import APIError
from app.models import Membership, Organization, SecurityEvent
from app.policy.engine import CATEGORIES
from app.schemas.security_event import SecurityEventPage, SecurityEventRead

router = APIRouter(prefix="/api/v1/security-events", tags=["security events"])


def visible_events(user):
    organizations = select(Membership.organization_id).join(Organization).where(
        Membership.user_id == user.id, Organization.status == "active")
    return select(SecurityEvent).where(SecurityEvent.organization_id.in_(organizations))


@router.get("", response_model=SecurityEventPage)
def list_events(session: DB, user: Admin, organization_id: UUID | None = None,
                application_id: UUID | None = None,
                decision: Literal["allow", "block", "review", "restrict"] | None = None,
                risk_level: Literal["low", "medium", "high", "critical"] | None = None,
                category: Annotated[str | None, Query(max_length=64)] = None,
                from_: Annotated[AwareDatetime | None, Query(alias="from")] = None,
                to: AwareDatetime | None = None, limit: Limit = 50, cursor: Cursor = None):
    if category is not None and category not in CATEGORIES:
        raise APIError(422, "validation_error", "Unknown event category.")
    if from_ is not None and to is not None and from_ > to:
        raise APIError(422, "validation_error", "Invalid event date range.")
    if organization_id:
        require_membership(session, user, organization_id)
    if application_id:
        application = application_for(session, user, application_id)
        if organization_id and application.organization_id != organization_id:
            raise APIError(404, "not_found", "Application not found.")
    statement = visible_events(user)
    for field, value in (("organization_id", organization_id), ("application_id", application_id),
                         ("decision", decision), ("risk_level", risk_level)):
        if value is not None:
            statement = statement.where(getattr(SecurityEvent, field) == value)
    if category is not None:
        statement = statement.where(SecurityEvent.categories.contains([category]))
    if from_ is not None:
        statement = statement.where(SecurityEvent.created_at >= from_)
    if to is not None:
        statement = statement.where(SecurityEvent.created_at <= to)
    context = "events:" + ":".join(str(value) for value in (
        user.id, organization_id, application_id, decision, risk_level, category,
        from_.isoformat() if from_ else None, to.isoformat() if to else None))
    return paginate(session, statement, SecurityEvent, limit, cursor, context)


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(event_id: UUID, session: DB, user: Admin):
    event = session.scalar(visible_events(user).where(SecurityEvent.id == event_id))
    if event is None:
        raise APIError(404, "not_found", "Security event not found.")
    return event
