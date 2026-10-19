"""Redis admission before identity verification and before management handlers."""
import hashlib
import ipaddress
from uuid import UUID

from fastapi import Depends, Request

from app.core.auth import get_admin
from app.core.config import settings
from app.core.database import redis_client
from app.core.errors import APIError
from app.core.rate_limit import GatewayRateLimiter


class ManagementRateLimiter(GatewayRateLimiter):
    unavailable_message = "Management admission unavailable."
    exceeded_message = "Management request quota exceeded."

    def bucket_key(self, scope, identifier):
        if scope == "source":
            # Never use arbitrary request headers as identity or Redis keys.
            value = str(ipaddress.ip_address(identifier))
        elif scope in {"user", "write"} and isinstance(identifier, UUID):
            value = str(identifier)
        else:
            raise ValueError("Verified admission identity required")
        digest = hashlib.sha256(value.encode("ascii")).hexdigest()
        return f"{self.prefix}:{scope}:{self.limit}:{self.window_ms}:{digest}"

    def admit(self, scope, identifier):
        try:
            key = self.bucket_key(scope, identifier)
        except (ValueError, TypeError) as exc:
            raise APIError(503, "service_unavailable", self.unavailable_message) from exc
        return self.check_key(key)


def get_management_limiter():
    def limiter(limit):
        return ManagementRateLimiter(redis_client, limit, settings.management_rate_limit_window_seconds,
                                     settings.management_rate_limit_prefix)
    return {"source": limiter(settings.management_source_limit_requests),
            "user": limiter(settings.management_user_limit_requests),
            "write": limiter(settings.management_write_limit_requests)}


def management_source_admission(request: Request, limiters=Depends(get_management_limiter)):
    if request.client is None:
        raise APIError(503, "service_unavailable", "Management admission unavailable.")
    limiters["source"].admit("source", request.client.host)


def management_user_admission(request: Request, user=Depends(get_admin),
                              limiters=Depends(get_management_limiter)):
    limiters["user"].admit("user", user.id)
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        limiters["write"].admit("write", user.id)
