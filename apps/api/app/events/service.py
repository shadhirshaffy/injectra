from dataclasses import asdict
import hashlib
import json
from uuid import UUID

from sqlalchemy import select

from app.core.errors import APIError
from app.detection import scan
from app.models import APIKey, Policy, PolicyVersion, SecurityEvent
from app.policy import PolicySnapshot, evaluate
from app.schemas.policy import PolicyRules


def safe_metadata(metadata):
    if metadata is None:
        return {}
    try:
        if not isinstance(metadata, dict) or any(not isinstance(key, str) for key in metadata):
            raise ValueError
        if len(json.dumps(metadata, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 4096:
            raise ValueError
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise APIError(422, "validation_error", "Invalid event metadata.") from exc
    # Enumerated strings prevent secrets from being smuggled into arbitrary values.
    source = metadata.get("source")
    return {"source": source} if isinstance(source, str) and source in {"chat", "api", "rag", "tool", "batch"} else {}


def record_scan_event(session, identity, request_id, input_text, scan_result, policy_decision,
                      content_type="prompt", metadata=None):
    """Trusted internal callers only. Flushes; caller must commit before success.

    Revalidates evidence and its historical policy snapshot. A write failure
    raises 503 and never returns a fabricated event ID or success decision.
    """
    filtered_metadata = safe_metadata(metadata)
    try:
        if not isinstance(request_id, UUID):
            raise ValueError
        # Verify input/evidence correspondence; never persist caller-supplied prose.
        evidence = scan(input_text, content_type)
        if evidence != scan_result:
            raise ValueError
        key = session.scalar(select(APIKey).where(
            APIKey.id == identity.api_key.id,
            APIKey.organization_id == identity.organization.id,
            APIKey.application_id == identity.application.id))
        if key is None:
            raise ValueError
        snapshot = PolicySnapshot()
        if policy_decision.policy_id is not None:
            row = session.execute(select(Policy, PolicyVersion).join(
                PolicyVersion, PolicyVersion.policy_id == Policy.id).where(
                    Policy.id == policy_decision.policy_id,
                    Policy.organization_id == identity.organization.id,
                    Policy.application_id == identity.application.id,
                    PolicyVersion.version == policy_decision.policy_version)).one_or_none()
            if row is None:
                raise ValueError
            _, version = row
            snapshot = PolicySnapshot(policy_decision.policy_id, version.version,
                                      tuple(PolicyRules.model_validate(version.rules).blocked_categories))
        expected = evaluate(evidence, snapshot)
        if expected != policy_decision:
            raise ValueError
        event = SecurityEvent(
            organization_id=identity.organization.id, application_id=identity.application.id,
            api_key_id=key.id, request_id=request_id,
            event_type="response_scan" if content_type == "response" else "prompt_scan",
            content_type=content_type, decision=expected.decision, risk_level=evidence.risk_level,
            risk_score=evidence.risk_score, categories=list(evidence.categories),
            matched_rules=[asdict(rule) for rule in evidence.matched_rules],
            reason=expected.reason, ruleset_version=evidence.ruleset_version,
            policy_id=expected.policy_id, policy_version=expected.policy_version,
            input_hash=hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
            redacted_input=None, event_metadata=filtered_metadata,
        )
        session.add(event)
        session.flush()
        return event
    except Exception as exc:
        raise APIError(503, "service_unavailable", "Security event persistence unavailable.") from exc
