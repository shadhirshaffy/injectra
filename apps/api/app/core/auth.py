import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_session
from app.core.errors import APIError
from app.models import APIKey, Application, Membership, Organization, User


bearer_scheme = HTTPBearer(auto_error=False)


def bearer(request: Request) -> str:
    parts = request.headers.get("authorization", "").split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise APIError(401, "invalid_api_key", "Valid bearer credentials are required.")
    return parts[1]


def get_admin(
    request: Request, session: Session = Depends(get_session),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User:
    # A fixed, operator-configured identity; public headers never select a user.
    if (settings.app_environment != "development" or not settings.dev_admin_enabled
            or not request.client or request.client.host not in {"127.0.0.1", "::1"}
            or not settings.dev_admin_subject or not settings.dev_admin_token
            or len(settings.dev_admin_token.get_secret_value()) < 32):
        raise APIError(401, "invalid_api_key", "Management authentication is required.")
    if not hmac.compare_digest(bearer(request).encode(), settings.dev_admin_token.get_secret_value().encode()):
        raise APIError(401, "invalid_api_key", "Management authentication is required.")
    user = session.scalar(select(User).where(User.identity_subject == settings.dev_admin_subject))
    if user is None or user.status != "active":
        raise APIError(401, "invalid_api_key", "An active management user is required.")
    return user


def require_membership(session, user, organization_id, manage=False):
    membership = session.scalar(select(Membership).where(
        Membership.organization_id == organization_id, Membership.user_id == user.id))
    organization = session.get(Organization, organization_id)
    if membership is None or organization is None:
        raise APIError(404, "not_found", "Organization not found.")
    if organization.status != "active" or (manage and membership.role not in {"owner", "admin"}):
        raise APIError(403, "forbidden", "Insufficient organization permissions.")
    return organization


def hash_key(key):
    if not settings.api_key_pepper or len(settings.api_key_pepper.get_secret_value()) < 32:
        raise APIError(503, "service_unavailable", "API key configuration unavailable.")
    return hmac.new(settings.api_key_pepper.get_secret_value().encode(), key.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class GatewayIdentity:
    organization: Organization
    application: Application
    api_key: APIKey


def require_gateway_scope(scope="gateway:scan"):
    def authenticate(
        request: Request, session: Session = Depends(get_session),
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    ):
        token = bearer(request)
        if not re.fullmatch(r"inj_live_[0-9a-f]{16}_[A-Za-z0-9_-]{43}", token):
            raise APIError(401, "invalid_api_key", "Invalid API key.")
        prefix = token[:25]
        key = session.scalar(select(APIKey).where(APIKey.key_prefix == prefix))
        presented_hash = hash_key(token)
        if key is None or not hmac.compare_digest(key.key_hash, presented_hash):
            raise APIError(401, "invalid_api_key", "Invalid API key.")
        if key.revoked_at is not None:
            raise APIError(401, "revoked_api_key", "API key has been revoked.")
        if key.expires_at is not None and key.expires_at <= datetime.now(timezone.utc):
            raise APIError(401, "expired_api_key", "API key has expired.")
        organization = session.get(Organization, key.organization_id)
        application = session.get(Application, key.application_id)
        if (organization is None or application is None or organization.status != "active"
                or application.status != "active" or application.organization_id != organization.id):
            raise APIError(401, "invalid_api_key", "Invalid API key.")
        if scope not in key.scopes:
            raise APIError(403, "missing_scope", "Required scope is missing.")
        return GatewayIdentity(organization, application, key)
    return authenticate
