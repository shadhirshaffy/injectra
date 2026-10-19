# Gateway Rate Limiting

## Behavior

`POST /api/v1/gateway/scan` requires Redis-backed admission after successful key
authentication and body validation, before detection, policy evaluation, or event
writes. The default is 60 admitted scans per application in a 60-second window.
All API keys for the same application share the quota across identically configured
API workers. Different applications and organizations have independent quotas.
Caller headers, IP addresses, and body fields cannot select a different bucket.

The window begins with the application's first admitted request and expires using
Redis TTL. A fixed Lua script atomically reads/updates the counter and assigns
expiry. Denials neither extend the window nor grow the counter. The implementation
uses one key per active application/configuration and constant-time commands.
There is no process-local fallback, quota bypass flag, client-supplied clock,
timer job, or database migration.

Successful scan responses include:

| Header | Meaning |
| --- | --- |
| X-RateLimit-Limit | Application request capacity per window |
| X-RateLimit-Remaining | Remaining capacity at this admission decision |
| X-RateLimit-Reset-After | Seconds until reset, rounded up; not an epoch timestamp |

Quota exhaustion returns HTTP 429 with the same headers, `Retry-After` in seconds,
and the standard safe error body with code `rate_limited`. The canonical request ID
and `Cache-Control: no-store` are retained. Admission denial does not run the
scanner or create a database scan event. Rate-limit rejection event producers and
aggregate monitoring are deferred to operational instrumentation; this avoids
turning excess traffic into unbounded database writes.

Redis connection, timeout, script, malformed-response, and corrupt-counter errors
return generic HTTP 503 `service_unavailable`, without scanning or forwarding.
Redis credentials, commands, keys, API keys, and prompt content are not echoed.
Redis operations have one-second connect/read timeouts and no automatic retries,
because replaying an uncertain operation may double-charge capacity.

Admission consumes quota even if a later detector, policy, persistence, or commit
operation fails. Redis admission and PostgreSQL commit are separate operations;
there is no refund. Clients should honor Retry-After on 429 and back off on 503.
Rejected/invalid credentials and invalid scan bodies do not consume quota.

## Configuration and operations

```dotenv
REDIS_URL=redis://127.0.0.1:6379/0
GATEWAY_RATE_LIMIT_REQUESTS=60
GATEWAY_RATE_LIMIT_WINDOW_SECONDS=60
GATEWAY_RATE_LIMIT_PREFIX=injectra:gateway-rate:v1
```

Requests must be 1–1,000,000 and window seconds 1–3600. Prefixes are 1–100 ASCII
letters/digits/colon/underscore/hyphen. Invalid settings prevent startup. Use a
unique prefix per environment and identical settings across all replicas.
Keys include server-resolved organization/application UUIDs and the configured
capacity/window, never credentials or input. Changing quota settings or prefix
starts new buckets; coordinate rolling deployments to avoid split configurations.
Existing keys naturally expire after their original windows.

The existing Compose Redis 7 service supports the required Lua, GET, SET, INCR,
and PTTL operations. Production Redis must allow these commands, have sufficient
memory, and use a no-eviction policy for quota state. Protect it with private
network access, credentials/TLS where applicable, and least-privilege ACLs. Do not
use Redis flush commands for deployment or tests. Memory pressure under no-eviction
causes admission to fail closed. Lost or evicted counter state resets that bucket's
quota; the limiter does not promise durable quotas across data loss or failover.

This is a fixed-window limit, not a sliding-window or token-bucket limiter. Up to
twice the nominal capacity can occur around adjacent window boundaries. It is
also an admission-rate limit, not a concurrency or request-body-size limit. Plan
ingress protection for unauthenticated traffic and management/invitation abuse
separately. Per-customer configurable plans and management rate limits are future
work.

The public health route remains liveness-only: it does not establish Redis or
PostgreSQL readiness. Deploy Redis before this application version; otherwise
scan requests return 503. Roll back by deploying the previous application version
under review, rather than silently bypassing an unavailable limiter. The frontend
CORS configuration exposes quota and Retry-After headers to authorized origins.

## Verification

From `apps/api`, with PostgreSQL and Redis running:

```powershell
python -m pytest tests/test_rate_limit.py
python -m pytest
```

Tests use real Redis scripts with random per-test namespaces and remove only
explicitly tracked test keys. They never clear a Redis database or production
quota prefix. Coverage includes exact concurrent capacity across separate limiter
instances, independent application/tenant quotas, expiry/reset, shared quota across
rotated API keys, TTL corruption, malformed replies, sanitized dependency failure,
HTTP header/error behavior, pre-scan rejection, invalid-request exclusion, and
no-refund behavior after downstream failure.

Unrelated gateway tests override the admission dependency to isolate their existing
contracts from Redis. Dedicated endpoint tests use the real limiter. CI's backend
job now supplies both PostgreSQL and Redis; the standalone detection/policy job
remains dependency-free.

References: [Redis INCR patterns](https://redis.io/docs/latest/commands/incr/),
[atomic Lua execution](https://redis.io/docs/latest/develop/programmability/eval-intro/).

Local verification on 2026-10-19 (Asia/Colombo): 442 backend tests passed,
including 36 admission tests. Frontend lint/build, Compose configuration, and
whitespace checks passed. The existing AnyIO BlockingPortal warning remains.
