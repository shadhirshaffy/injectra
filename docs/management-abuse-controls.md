# Management API abuse controls

All registered management routes now require Redis admission: organizations,
applications, API keys, policies, security-event reads, `/me`, invitations and
memberships. No database migration is needed. Authentication and organization
permissions still apply independently.

Each fixed window starts with its first admitted request. Defaults are:

| Bucket | Default per 60 seconds | Identity |
| --- | ---: | --- |
| Source | 300 | Canonical connection IP before authentication |
| User | 120 | Verified internal user UUID across every organization and route |
| Writes | 30 | Same user, methods other than GET, HEAD and OPTIONS |

Configure `MANAGEMENT_SOURCE_LIMIT_REQUESTS`, `MANAGEMENT_USER_LIMIT_REQUESTS`,
`MANAGEMENT_WRITE_LIMIT_REQUESTS`, `MANAGEMENT_RATE_LIMIT_WINDOW_SECONDS` and
`MANAGEMENT_RATE_LIMIT_PREFIX`; defaults are in `infrastructure/.env.example`.
Counts must be 1–1,000,000 and windows 1–3,600 seconds. Prefixes accept only
letters, digits, colons, underscores and hyphens, with a 100-character maximum.
Changing a limit, window or prefix creates a fresh bucket namespace. Roll out
configuration consistently across workers to avoid independent quotas.

The source bucket runs before the identity dependency, limiting missing/invalid
credentials and provider checks. Successful authentication then consumes the
user bucket, and writes also consume the write bucket before the route handler.
JWT verification, live write-session verification and user resolution occur
before the user quota. Rate limiting grants no organization access and does not
trust user IDs, organization headers, bearer-token fragments or request IDs.

All workers use the existing constant-time atomic Lua admission script. Each
bucket has a TTL; rejected requests do not extend it or grow its counter.
Concurrent requests share exact capacity. Multiple bucket checks are sequential,
so a later denial consumes earlier quotas. Invalid bodies, permission failures
and downstream errors may also consume quota. No refunds are issued. Fixed
windows allow bursts across window boundaries; there is no sliding-window or
concurrency guarantee.

A denial returns the standard privacy-safe 429 error with `Retry-After` and
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset-After` for the
bucket that rejected it. Successful responses do not advertise these multiple
quotas. Redis outages, malformed state or invalid source identities return 503
before the handler; there is no process-local fallback. Request IDs, no-store
responses and configured CORS exposure remain available.

Redis keys contain SHA-256 digests of IPs or internal user UUIDs, a scope and
configuration values. They contain no raw IP, user ID, email, JWT, invitation
token, prompt or API-key material. Digests are pseudonymous, not anonymous:
IP addresses can be enumerated. Restrict Redis access, use transport security
when remote, and apply the Redis backup/access policy. Cleanup is automatic via
short TTLs; this feature creates no security-event rows or database records.

## Deployment and remaining controls

Run Uvicorn with `--no-proxy-headers` when exposed directly. Admission reads the
ASGI connection address and never parses `Forwarded` or `X-Forwarded-For` itself.
Uvicorn or another upstream component can already rewrite that address. Behind a
reverse proxy, either preserve its connection address and accept one shared
source quota, or explicitly configure only trusted proxy addresses and require
the proxy to overwrite untrusted forwarding headers. Do not trust `*` on a public
listener. Test the effective source address through your deployment before launch.
Users behind a shared NAT/proxy can exhaust a shared source quota; adjust this
limit based on observed traffic without weakening user/write quotas.

Gateway scan admission remains per application and uses its existing independent
namespace. Health, OpenAPI/docs, CORS preflight, unknown paths and unsupported
methods are outside these management dependencies. Maintain edge controls for
request/body size, connection count, distributed traffic and public invalid
paths; application quotas do not replace an edge firewall. Large/malformed JSON
may be parsed before dependencies run. The development identity adapter also
uses these controls. Operator CLI commands are outside the HTTP quotas.

Live Clerk remains unconfigured until the operator supplies its application
configuration. No live provider account or deployment setting was changed.

## Verification

From `apps/api`: `python -m pytest tests/test_management_admission.py
tests/test_rate_limit.py`, then `python -m pytest`. Integration tests use random
Redis namespaces and disposable PostgreSQL schemas; no FLUSHDB is used.
Coverage includes pre-auth denial, ignored forwarding headers, independent user
and write quotas, blocked mutations, shared routes, atomic concurrent capacity,
configuration bounds and safe Redis outage responses. Existing gateway tests
continue to validate counter expiry, corrupt states and admission failures.
