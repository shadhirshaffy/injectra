from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select, text

from app.api.management import Admin, Cursor, DB, Limit, application_for, paginate
from app.core.errors import APIError
from app.models import Application, Policy, PolicyVersion
from app.policy.service import read_policy
from app.schemas.policy import PolicyRead, PolicyVersionPage, PolicyWrite

router = APIRouter(prefix="/api/v1/applications", tags=["policies"])


def policy_response(application, policy):
    return dict(
        id=policy.id if policy else None, organization_id=application.organization_id,
        application_id=application.id, name=policy.name if policy else "Default policy",
        version=policy.current_version if policy else 0,
        source="configured" if policy else "default",
        rules=policy.rules if policy else {"blocked_categories": []},
        created_at=policy.created_at if policy else None,
        updated_at=policy.updated_at if policy else None,
    )


@router.get("/{application_id}/policy", response_model=PolicyRead)
def get_policy(application_id: UUID, session: DB, user: Admin):
    application = application_for(session, user, application_id)
    return policy_response(application, read_policy(session, application.organization_id, application.id))


@router.put("/{application_id}/policy", response_model=PolicyRead)
def update_policy(application_id: UUID, body: PolicyWrite, session: DB, user: Admin):
    application = application_for(session, user, application_id, manage=True)
    session.execute(text("SET LOCAL lock_timeout = '5s'"))
    # Serialize even the first write, when there is no policy row to lock.
    application = session.scalar(select(Application).where(
        Application.id == application_id,
        Application.organization_id == application.organization_id).with_for_update()
        .execution_options(populate_existing=True))
    if application.status != "active":
        raise APIError(403, "forbidden", "Application is inactive.")
    policy = read_policy(session, application.organization_id, application.id)
    current = policy.current_version if policy else 0
    if body.expected_version != current:
        raise APIError(409, "conflict", "Policy version changed. Read the current policy before retrying.")
    if policy is None:
        policy = Policy(organization_id=application.organization_id, application_id=application.id,
                        name=body.name, current_version=1, rules=body.rules.model_dump())
        session.add(policy)
    else:
        policy.name = body.name
        policy.current_version += 1
        policy.rules = body.rules.model_dump()
        policy.updated_at = datetime.now(timezone.utc)
    session.flush()
    session.add(PolicyVersion(policy_id=policy.id, version=policy.current_version,
        name=policy.name, rules=policy.rules, created_by_user_id=user.id))
    session.flush()
    return policy_response(application, policy)


@router.get("/{application_id}/policy/versions", response_model=PolicyVersionPage)
def list_versions(application_id: UUID, session: DB, user: Admin,
                  limit: Limit = 50, cursor: Cursor = None):
    application = application_for(session, user, application_id)
    statement = select(PolicyVersion).join(Policy).where(
        Policy.organization_id == application.organization_id, Policy.application_id == application.id)
    return paginate(session, statement, PolicyVersion, limit, cursor,
                    f"policy_versions:{application.organization_id}:{application.id}")
