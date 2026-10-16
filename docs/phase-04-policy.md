# Phase 4 — Versioned Application Policies

## Behavior

The pure `app.policy.evaluate` engine consumes immutable scanner evidence and an
immutable `PolicySnapshot`. It returns `PolicyDecision` with `decision`, static
`reason`, `policy_id`, and `policy_version`. Only `can_forward == True` authorizes
forwarding. `review` is not permission to forward. There is no provider invocation,
event persistence, dashboard, or public scan endpoint in this milestone.

Default mapping: low → allow, medium → review, high/critical → block. Application
policies may add explicit category blocks; they cannot weaken that mapping.
`restrict` remains reserved for later tool-level enforcement. Missing policy rows
use the built-in default (ID null, version 0); no row is created on a default read.

Trusted callers may supply `HardDeny` values for invalid/revoked/expired keys,
missing scopes, tenant mismatch, or unauthorized tools. Any such denial blocks,
including when scan evidence is unavailable. Gateway authentication still rejects
invalid credentials before evaluation, using the existing HTTP error contract.
These denials are not public request fields and do not replace authentication.

Without a hard denial, malformed evidence, unknown scanner versions, unknown rule
IDs, inconsistent scores, and invalid policies raise `PolicyEvaluationError`.
The database-backed `evaluate_for_application` adapter verifies active tenant/
application ownership, reads one coherent policy/version snapshot, and converts
lookup or evaluation failures to a safe `503 service_unavailable`. A failed lookup
is never treated as an absent policy. It rejects missing, inconsistent, or invalid
configured history instead of using defaults. The adapter accepts only IDs from
trusted authenticated context; it is not itself an authentication mechanism.

## Management API

All endpoints use the existing management identity dependency. Organization
members may read policy/history. Only owners/admins may write. Foreign resources
return 404, insufficient roles 403, invalid bodies 422, stale versions 409, and
unavailable dependencies 503. Customer application API keys cannot manage policy.
Inactive organizations cannot access management routes; inactive applications
cannot receive policy writes. Production management authentication remains pending.

### GET `/api/v1/applications/{application_id}/policy`

Returns `id`, `organization_id`, `application_id`, `name`, `version`, `source`,
`rules`, `created_at`, and `updated_at`. `source` is `default` or `configured`.
The default has null timestamps, name `Default policy`, and empty blocked categories.

### PUT `/api/v1/applications/{application_id}/policy`

```json
{
  "name": "Application policy",
  "expected_version": 0,
  "rules": {"blocked_categories": ["obfuscation"]}
}
```

Use expected version 0 for the first configured policy; subsequent writes must
match the current version. `name` defaults to `Application policy`, is trimmed,
and must contain 1–150 characters. `rules` and `blocked_categories` are required.
Categories must be unique members of the eight scanner categories and are stored
sorted. Unknown fields and coercion of the expected version are rejected. Success
returns 200 with the current policy representation. Every accepted write creates
a new immutable version, including an unchanged configuration. To remove category
blocks, submit an empty list with the current expected version; history remains.

### GET `/api/v1/applications/{application_id}/policy/versions`

Returns `{ "items": [], "next_cursor": null }` with existing limit/cursor
semantics (default 50, range 1–100). Each item contains its ID, policy ID, version,
name, rules, creator user ID, and UTC creation timestamp. Ordering uses
`created_at DESC, id DESC`; cursors are bound to organization and application.

## Persistence and concurrency

Migration `b703e4a12c09` adds `policies` and `policy_versions` without changing
identity data. Composite application/organization foreign keys preserve tenant
ownership. Unique constraints enforce one policy per application and one snapshot
per policy/version; a partial unique index also enforces one active application
policy. Positive version and active status checks are database enforced.

Updates acquire the application row lock, including first writes where no policy
exists. A transaction-local five-second lock timeout bounds contention. After the
lock, the service verifies the expected version, updates the current policy, and
inserts its snapshot in the same transaction. Concurrent writers using the same
expected version produce one successful update and one 409. Partial writes roll
back if snapshot creation fails. Reads join current version and policy in one
statement to avoid mixed snapshots under READ COMMITTED.

PostgreSQL triggers reject UPDATE and DELETE on history rows. History and creator
foreign keys use RESTRICT: deleting a policy, creator, or owning tenant with
history is intentionally blocked. No deletion or history editing API is provided;
retention/deletion workflows require a separately reviewed future migration.

## Deployment, verification, and rollback

Apply migrations before exposing policy management routes:

```powershell
cd apps/api
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m pytest scanner_tests
```

Do not modify the stable API-key pepper. The migration has been tested in isolated
PostgreSQL schemas, including upgrade, schema drift detection, downgrade to Phase
2, and re-upgrade. It has not been applied to the local public application schema
automatically. Existing CI runs the policy integration suite with PostgreSQL and
the pure evaluator tests in the standalone job without application services.

Rollback should disable policy routes and revert the application while preserving
history tables. The migration downgrade removes policy data and must only be used
with an approved backup/data-loss plan outside disposable test schemas.

Before scan integration, persist the evaluated policy ID/version and scanner
ruleset version with each security event. Persist the event before returning a
successful scan response. The invocation layer must refuse forwarding unless the
decision explicitly authorizes it. Operational monitoring should count safe 503
and 409 error codes and investigate repeated policy availability failures; never
include prompts, rules payloads, or credentials in error logs.

Local verification on 2026-10-16 (Asia/Colombo): 291 backend tests passed,
including the policy evaluator, management API, concurrency, atomic rollback,
tenant isolation, immutable history, and migration roundtrip checks. The existing
AnyIO BlockingPortal deprecation warning remains. Phase 3 PR #1 completed all
four hosted CI jobs successfully before the Phase 4 delivery.
