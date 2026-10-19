from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.auth import GatewayIdentity, require_gateway_scope
from app.core.database import get_session
from app.core.errors import APIError
from app.core.rate_limit import GatewayRateLimiter, get_gateway_limiter
from app.detection import scan
from app.events.service import record_scan_event
from app.policy.service import evaluate_for_application
from app.schemas.gateway import ScanRequest, ScanResponse

router = APIRouter(prefix="/api/v1/gateway", tags=["gateway"])
ScanIdentity = Annotated[GatewayIdentity, Depends(require_gateway_scope("gateway:scan"))]


@router.post("/scan", response_model=ScanResponse)
def scan_prompt(body: ScanRequest, request: Request, response: Response, identity: ScanIdentity,
                session: Annotated[Session, Depends(get_session)],
                limiter: Annotated[GatewayRateLimiter, Depends(get_gateway_limiter)]):
    # Outside pipeline error wrapping so a quota denial stays 429, not 503.
    admission = limiter.check(identity)
    response.headers.update(admission.headers())
    try:
        evidence = scan(body.input, body.content_type)
        decision = evaluate_for_application(session, identity.organization.id,
                                            identity.application.id, evidence)
        request_id = UUID(request.state.request_id)
        event = record_scan_event(session, identity, request_id, body.input, evidence,
                                  decision, body.content_type, body.metadata)
        # Materialize/validate while the transaction is open; returning an ORM
        # object after commit could trigger a new read or expose an unsaved ID.
        response = ScanResponse(
            request_id=request_id, organization_id=identity.organization.id,
            application_id=identity.application.id, decision=decision.decision,
            risk_level=evidence.risk_level, risk_score=evidence.risk_score,
            categories=list(evidence.categories), matched_rules=list(evidence.matched_rules),
            reason=decision.reason, event_id=event.id, ruleset_version=evidence.ruleset_version,
            policy_id=decision.policy_id, policy_version=decision.policy_version,
        )
        # A flush is not durable. Commit failures must become 503 before 200.
        session.commit()
        return response
    except Exception as exc:
        session.rollback()
        raise APIError(503, "service_unavailable", "Security inspection unavailable.") from exc
