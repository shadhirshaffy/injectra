"""Tenant-scoped persistence and fail-closed integration adapter."""
from pydantic import ValidationError
from sqlalchemy import select

from app.core.errors import APIError
from app.models import Application, Organization, Policy, PolicyVersion
from app.policy.engine import PolicyEvaluationError, PolicySnapshot, evaluate
from app.schemas.policy import PolicyRules


def read_policy(session, organization_id, application_id):
    # One statement gives a coherent policy/version snapshot under READ COMMITTED.
    row = session.execute(select(Policy, PolicyVersion).outerjoin(
        PolicyVersion, (PolicyVersion.policy_id == Policy.id)
        & (PolicyVersion.version == Policy.current_version)
    ).where(Policy.organization_id == organization_id, Policy.application_id == application_id)
      .execution_options(populate_existing=True)).one_or_none()
    if row is None:
        return None
    policy, version = row
    try:
        if (policy.status != "active" or version is None or policy.rules != version.rules
                or policy.name != version.name):
            raise ValueError
        PolicyRules.model_validate(version.rules)
    except (ValidationError, ValueError, TypeError) as exc:
        raise APIError(503, "service_unavailable", "Policy unavailable.") from exc
    return policy


def evaluate_for_application(session, organization_id, application_id, scan_result, hard_denies=()):
    """Caller must supply trusted IDs from verified gateway identity, never body IDs."""
    try:
        active = session.scalar(select(Application.id).join(Organization).where(
            Application.id == application_id, Application.organization_id == organization_id,
            Application.status == "active", Organization.status == "active"))
        if active is None:
            raise PolicyEvaluationError("Application identity unavailable.")
        policy = read_policy(session, organization_id, application_id)
        snapshot = PolicySnapshot() if policy is None else PolicySnapshot(
            policy.id, policy.current_version,
            tuple(PolicyRules.model_validate(policy.rules).blocked_categories))
        return evaluate(scan_result, snapshot, hard_denies)
    except Exception as exc:
        # This security boundary converts unexpected evaluator/lookup failures
        # to unavailable, never a default policy or an allow decision.
        raise APIError(503, "service_unavailable", "Policy evaluation unavailable.") from exc
