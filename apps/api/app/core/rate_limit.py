"""Atomic per-application scan admission; no process-local fallback."""
from dataclasses import dataclass
from math import ceil
import re
from uuid import UUID

from app.core.config import settings
from app.core.database import redis_client
from app.core.errors import APIError

# One key and a fixed script keep each operation atomic and constant-time.
# Denials do not extend expiry or grow the counter. Missing TTL is corruption,
# not permission to reset a live application's quota.
ADMIT_SCRIPT = """
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current = redis.call('GET', KEYS[1])
if not current then
    redis.call('SET', KEYS[1], '1', 'PX', window)
    return {1, limit - 1, window}
end
local count = tonumber(current)
local ttl = redis.call('PTTL', KEYS[1])
if #current > 7 or not string.match(current, '^[1-9][0-9]*$') or not count
    or count < 1 or count > limit or count ~= math.floor(count) or ttl < 0 or ttl > window then
    return redis.error_reply('Invalid admission state')
end
if count >= limit then
    return {0, 0, ttl}
end
redis.call('INCR', KEYS[1])
return {1, limit - count - 1, ttl}
"""


@dataclass(frozen=True)
class Admission:
    limit: int
    remaining: int
    reset_after_seconds: int

    def headers(self):
        return {"X-RateLimit-Limit": str(self.limit),
                "X-RateLimit-Remaining": str(self.remaining),
                "X-RateLimit-Reset-After": str(self.reset_after_seconds)}


class GatewayRateLimiter:
    unavailable_message = "Gateway admission unavailable."
    exceeded_message = "Application scan quota exceeded."
    def __init__(self, client, limit, window_seconds, prefix):
        if (type(limit) is not int or not 1 <= limit <= 1_000_000
                or type(window_seconds) is not int or not 1 <= window_seconds <= 3600
                or not isinstance(prefix, str) or not re.fullmatch(r"[A-Za-z0-9:_-]{1,100}", prefix)):
            raise ValueError("Invalid gateway admission configuration")
        self.client, self.limit = client, limit
        self.window_ms, self.prefix = window_seconds * 1000, prefix

    def key(self, organization_id, application_id):
        if not isinstance(organization_id, UUID) or not isinstance(application_id, UUID):
            raise ValueError("Verified application identity required")
        return f"{self.prefix}:{self.limit}:{self.window_ms}:{{{organization_id}:{application_id}}}"

    def check(self, identity):
        try:
            key = self.key(identity.organization.id, identity.application.id)
        except Exception as exc:
            raise APIError(503, "service_unavailable", self.unavailable_message) from exc
        return self.check_key(key)

    def check_key(self, key):
        try:
            result = self.client.eval(ADMIT_SCRIPT, 1, key, self.limit, self.window_ms)
            if (not isinstance(result, (list, tuple)) or len(result) != 3
                    or any(type(item) is not int for item in result)):
                raise ValueError("Invalid admission response")
            allowed, remaining, ttl_ms = result
            if (allowed not in (0, 1) or not 0 <= remaining < self.limit
                    or not 0 <= ttl_ms <= self.window_ms or (allowed == 0 and remaining != 0)):
                raise ValueError("Invalid admission response")
            admission = Admission(self.limit, remaining, max(1, ceil(ttl_ms / 1000)))
        except Exception as exc:
            raise APIError(503, "service_unavailable", self.unavailable_message) from exc
        if not allowed:
            raise APIError(429, "rate_limited", self.exceeded_message,
                           headers={**admission.headers(), "Retry-After": str(admission.reset_after_seconds)})
        return admission


def get_gateway_limiter():
    return GatewayRateLimiter(redis_client, settings.gateway_rate_limit_requests,
        settings.gateway_rate_limit_window_seconds, settings.gateway_rate_limit_prefix)
