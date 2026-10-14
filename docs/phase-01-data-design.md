# Injectra Phase 1 Data Design

## Existing Tables

The current project already includes:

- `organizations`
- `users`
- `memberships`
- `applications`
- `api_keys`

These tables are a good base for a multi-tenant SaaS gateway.

## Existing Relationship Summary

```text
organizations 1 -> many memberships
users         1 -> many memberships
organizations 1 -> many applications
organizations 1 -> many api_keys
applications  1 -> many api_keys
```

Important existing constraints:

- `users.identity_subject` is unique.
- `(memberships.organization_id, memberships.user_id)` is unique.
- `(applications.organization_id, applications.name)` is unique.
- `(applications.id, applications.organization_id)` is unique.
- `api_keys.key_prefix` is unique.
- `api_keys(application_id, organization_id)` references `applications(id, organization_id)`.

The composite API key to application constraint is important because it prevents accidentally assigning a key to an application from another organization.

## Recommended Phase 2 Table Adjustments

No existing table needs to be removed for Phase 2.

Recommended additions to current models:

- Add `updated_at` to mutable tables in future migrations.
- Add `name` or `label` to `api_keys` so dashboard users can identify keys.
- Add `last_used_at` to `api_keys` later for monitoring.

For Phase 2, avoid changing existing migrations unless necessary. Add new migrations instead.

## New Tables For Later Phases

## `policies`

Stores active policy per application.

Fields:

- `id`: UUID primary key.
- `organization_id`: UUID, required.
- `application_id`: UUID, required.
- `name`: string, required.
- `status`: string, default `active`.
- `rules`: JSONB, required.
- `created_at`: timestamp.
- `updated_at`: timestamp.

Constraints:

- One active policy per application; this is the application default.
- Composite FK to application and organization.

## `policy_versions`

Stores history of policy changes.

Fields:

- `id`: UUID primary key.
- `policy_id`: UUID, required.
- `version`: integer, required.
- `rules`: JSONB, required.
- `created_by_user_id`: UUID, nullable for system-created policies.
- `created_at`: timestamp.

Constraints:

- `(policy_id, version)` unique.

## `security_events`

Stores tenant-attributed prompt scan, response scan, gateway, policy, and verified authentication events. Unattributed authentication failures use separate operational logs.

Fields:

- `id`: UUID primary key.
- `organization_id`: UUID, required.
- `application_id`: UUID, required.
- `api_key_id`: UUID, nullable.
- `request_id`: UUID, required.
- `event_type`: string, required.
- `decision`: string, required.
- `risk_level`: string, required.
- `risk_score`: numeric, required.
- `categories`: JSONB, required.
- `matched_rules`: JSONB, required.
- `reason`: text, required.
- `input_hash`: string, nullable.
- `redacted_input`: text, nullable.
- `metadata`: JSONB, required.
- `created_at`: timestamp.

Suggested indexes:

- `(organization_id, created_at)`
- `(application_id, created_at)`
- `(request_id)`
- `(decision)`
- `(risk_level)`

Allowed `event_type` values:

- `prompt_scan`
- `response_scan`
- `gateway_invoke`
- `auth_failure`
- `policy_block`
- `rate_limit`

Allowed `decision` values:

- `allow`
- `block`
- `review`
- `restrict`

Allowed `risk_level` values:

- `low`
- `medium`
- `high`
- `critical`

## `usage_records`

Stores usage counters for SaaS limits and later billing.

Fields:

- `id`: UUID primary key.
- `organization_id`: UUID, required.
- `application_id`: UUID, nullable.
- `period_start`: timestamp.
- `period_end`: timestamp.
- `metric_name`: string.
- `quantity`: integer.
- `created_at`: timestamp.

Metrics:

- `gateway_scan_requests`
- `gateway_invoke_requests`
- `blocked_requests`
- `llm_tokens_input`
- `llm_tokens_output`

## `provider_configs`

Stores LLM provider settings for an application.

Fields:

- `id`: UUID primary key.
- `organization_id`: UUID, required.
- `application_id`: UUID, required.
- `provider`: string, required.
- `model`: string, required.
- `encrypted_credentials_ref`: string, nullable.
- `settings`: JSONB, required.
- `status`: string, default `active`.
- `created_at`: timestamp.
- `updated_at`: timestamp.

Provider secrets must not be stored as plaintext.

## Data Retention Guidance

Default behavior:

- Store hashes and redacted excerpts rather than raw prompts.
- Keep full raw content disabled by default.
- Keep security event metadata minimal.
- Add retention settings before production launch.

Future retention settings:

- Security events: 30 to 365 days depending on plan.
- Raw prompt captures: disabled by default.
- Aggregated usage records: longer retention for billing and analytics.

## Phase 2 Database Acceptance Criteria

Phase 2 is database-ready when:

- Current migrations apply cleanly.
- Organization creation persists correctly.
- Application creation persists correctly.
- API key creation stores only hash and prefix.
- Revoked API keys have `revoked_at`.
- Cross-tenant application/key mismatches are rejected.


## Integrity and Implementation Decisions

- Use timezone-aware UTC timestamps throughout. Risk scores require a database check between 0 and 1; decision and risk values require check constraints.
- Security events, policies, usage records with an application, and provider configurations enforce application/organization ownership with composite foreign keys. Event API key references must also preserve tenant/application ownership when present.
- Policy versions are immutable. Store the evaluated policy version on each security event for reproducibility; allocate versions transactionally with the unique constraint. A partial unique index enforces one active policy per application.
- Map the SQLAlchemy attribute `event_metadata` to the database column `metadata`, since declarative models reserve `metadata`. Default JSON collections must use callable factories.
- Store only allowlisted metadata; raw prompt storage and redacted excerpts are opt-in. Hashes are correlation data, not anonymization. Define deletion/retention jobs before production.
- Phase 2 needs no schema changes for basic organization/application/key operations. Key labels, last-used timestamps, and updated timestamps are deferred. New tables belong to their implementation phases.
