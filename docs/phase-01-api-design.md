# Injectra Phase 1 API Design

## API Principles

- All product APIs use the `/api/v1` prefix.
- Responses are JSON.
- Errors use a consistent structure.
- Customer application requests authenticate with API keys.
- Admin dashboard requests will later authenticate with user sessions or JWTs.
- Client-provided tenant identifiers are always validated against authenticated identity.

## Common Error Format

```json
{
  "error": {
    "code": "invalid_api_key",
    "message": "The provided API key is invalid.",
    "request_id": "uuid",
    "details": {}
  }
}
```

Common error codes:

- `validation_error`
- `not_found`
- `invalid_api_key`
- `revoked_api_key`
- `expired_api_key`
- `missing_scope`
- `tenant_mismatch`
- `policy_blocked`
- `rate_limited`
- `internal_error`
- `forbidden`
- `conflict`
- `service_unavailable`

## Authentication

### API Key Authentication

Customer application requests use:

```text
Authorization: Bearer inj_live_xxxxxxxxx
```

Validation rules:

1. Extract bearer token.
2. Parse key prefix.
3. Find key by prefix, including revoked keys.
4. Hash presented key using the same algorithm used at creation.
5. Compare stored hash using constant-time comparison.
6. Reject if revoked or expired.
7. Resolve organization and application from the key record.
8. Check required scope.

Initial scopes:

- `gateway:scan`
- `gateway:invoke`
- `events:read`
- `keys:manage`

Phase 2 issues only `gateway:scan`; the other scopes are reserved for later phases.

## Management Authorization Contract

Organization, application, and API key routes are management endpoints. Customer application keys cannot create organizations or manage other applications. `keys:manage` is reserved until delegated key management is designed; Phase 2 issues only `gateway:scan` keys.

- Organization creation requires an authenticated active user and creates an owner membership in the same transaction.
- Organization reads and application reads require membership in the target organization.
- Application creation and key creation/revocation require an owner or admin membership. Key listing also requires owner or admin membership.
- Phase 2 must introduce a replaceable admin identity dependency. Until verified session/JWT authentication exists, a development identity adapter may be explicitly enabled for loopback-only local development, disabled by default. It must not trust public identity headers or body fields. Management endpoints reject unauthenticated access when the adapter is disabled.
- Cross-tenant resource lookups return `404 not_found`; authenticated users without the required role receive `403 forbidden`.
- The organization and application must be active for gateway authentication to succeed.

## Shared Contract Details

- Timestamps use UTC RFC 3339; identifiers are UUIDs.
- List endpoints return `{ "items": [], "next_cursor": null }`, ordered by `created_at DESC, id DESC`. `limit` defaults to 50 and accepts 1-100; cursors are opaque and validated within the authenticated tenant filter.
- Trim names before validating; reject blank names. Application uniqueness is case-sensitive within an organization. Duplicate names return `409 conflict`.
- Unknown or unsupported scopes are rejected with `422 validation_error`. Key expiration, when provided, must be a future UTC timestamp.
- Revocation is idempotent: return `200` with the original `revoked_at` on repeated calls.
- Missing, malformed, unknown, or incorrectly hashed credentials return `401 invalid_api_key` with `WWW-Authenticate: Bearer`. Only after secret verification may revoked/expired credentials return their specific `401` codes. Missing scope returns `403 missing_scope`.
- Body/query validation returns `422`; rate limits return `429` with `Retry-After`; unavailable security dependencies return `503 service_unavailable`. Unexpected errors return `500` without internal details.
- Scan decisions, including `block` and `review`, return `200`: inspection completed successfully. `review` and `restrict` do not authorize forwarding. `policy_blocked` is reserved for future invoke refusals.
- `content_type` defaults to `prompt`; metadata defaults to `{}` and is limited to 4 KiB of UTF-8 JSON. Risk scores are in `[0, 1]` and use the intervals in the security workflow.
- Injectra generates a canonical request ID for every request, includes it in error bodies and the `X-Request-ID` response header, and ignores public caller-supplied canonical IDs.

## Endpoint Plan

## Health

### `GET /api/v1/health`

No authentication.

Success response:

```json
{
  "status": "ok",
  "service": "injectra-api",
  "version": "0.1.0"
}
```

## Organizations

### `POST /api/v1/organizations`

Creates an organization.

Request:

```json
{
  "name": "Acme AI"
}
```

Validation:

- `name`: required, 1-150 characters.

Success response: `201 Created`

```json
{
  "id": "uuid",
  "name": "Acme AI",
  "status": "active",
  "created_at": "timestamp"
}
```

### `GET /api/v1/organizations/{organization_id}`

Returns one organization.

Success response: `200 OK`

### `GET /api/v1/organizations`

Returns organizations visible to the authenticated admin user.

Management endpoints require authenticated admin identity and membership checks as specified below.

## Applications

### `POST /api/v1/applications`

Creates an application inside an organization.

Request:

```json
{
  "organization_id": "uuid",
  "name": "Support Assistant"
}
```

Validation:

- `organization_id`: must exist.
- `name`: required, 1-150 characters.
- `(organization_id, name)` must be unique.

Success response: `201 Created`

```json
{
  "id": "uuid",
  "organization_id": "uuid",
  "name": "Support Assistant",
  "status": "active",
  "created_at": "timestamp"
}
```

### `GET /api/v1/applications/{application_id}`

Returns one application.

### `GET /api/v1/organizations/{organization_id}/applications`

Returns applications for one organization.

## API Keys

### `POST /api/v1/api-keys`

Creates an API key for an application.

Request:

```json
{
  "organization_id": "uuid",
  "application_id": "uuid",
  "scopes": ["gateway:scan"],
  "expires_at": null
}
```

Validation:

- Application must belong to the organization.
- Scopes must be from the allowed scope list.
- Expiration may be null.

Success response: `201 Created`

```json
{
  "id": "uuid",
  "organization_id": "uuid",
  "application_id": "uuid",
  "key": "inj_live_xxxxxxxxx",
  "key_prefix": "inj_live_abc123",
  "scopes": ["gateway:scan"],
  "expires_at": null,
  "created_at": "timestamp"
}
```

The full `key` value is returned only once.

### `GET /api/v1/applications/{application_id}/api-keys`

Returns API key metadata. Never returns full key or hash.

Response item:

```json
{
  "id": "uuid",
  "organization_id": "uuid",
  "application_id": "uuid",
  "key_prefix": "inj_live_abc123",
  "scopes": ["gateway:scan"],
  "expires_at": null,
  "revoked_at": null,
  "created_at": "timestamp"
}
```

### `POST /api/v1/api-keys/{api_key_id}/revoke`

Revokes an API key.

Success response:

```json
{
  "id": "uuid",
  "revoked_at": "timestamp"
}
```

## Gateway

### `POST /api/v1/gateway/scan`

Runs security inspection without forwarding to an LLM.

Phase 6 is implemented. See [scan API behavior](phase-06-scan.md) for the complete
request/response contract, additive ruleset/policy-version fields, and explicit
commit-before-success guarantee.

Required scope:

- `gateway:scan`

Request:

```json
{
  "input": "Prompt text to inspect",
  "content_type": "prompt",
  "metadata": {
    "source": "chat",
    "customer_user_id": "u_123"
  }
}
```

Validation:

- `input`: required, 1-20000 characters for MVP.
- `content_type`: `prompt`, `rag_context`, `tool_output`, or `response`.
- `metadata`: optional JSON object.

Success response:

```json
{
  "request_id": "uuid",
  "organization_id": "uuid",
  "application_id": "uuid",
  "decision": "block",
  "risk_level": "high",
  "risk_score": 0.67,
  "categories": ["instruction_override"],
  "matched_rules": [
    {
      "id": "rule_instruction_override_001",
      "name": "Instruction override attempt",
      "severity": "high"
    }
  ],
  "reason": "Prompt contains known instruction override patterns.",
  "event_id": "uuid"
}
```

### Future: `POST /api/v1/gateway/invoke`

Runs scan, policy, LLM forwarding, response inspection, and event logging.

Required scope:

- `gateway:invoke`

This endpoint should not be implemented until the scan endpoint is stable.

## Security Events

### `GET /api/v1/security-events`

Returns events visible to the authenticated tenant/admin.

Filters:

- `organization_id`
- `application_id`
- `decision`
- `risk_level`
- `category`
- `from`
- `to`
- `limit`
- `cursor`

Response:

```json
{
  "items": [
    {
      "id": "uuid",
      "request_id": "uuid",
      "organization_id": "uuid",
      "application_id": "uuid",
      "event_type": "prompt_scan",
      "decision": "block",
      "risk_level": "high",
      "categories": ["instruction_override"],
      "created_at": "timestamp"
    }
  ],
  "next_cursor": null
}
```

Phase 5 event read APIs are implemented. See [event contracts](phase-05-events.md)
for complete filtering, privacy, and tenant-authorization behavior, including the
additional `GET /api/v1/security-events/{event_id}` endpoint.

## Policies

### `GET /api/v1/applications/{application_id}/policy`

Returns active policy for an application.

### `PUT /api/v1/applications/{application_id}/policy`

Updates policy and creates a policy version.

Phase 2 does not need this endpoint. Phase 4 should implement it.

Phase 4 is implemented: see [policy contracts](phase-04-policy.md) for request and
response schemas, expected-version concurrency, and
`GET /api/v1/applications/{application_id}/policy/versions`. Policies can add
category blocks; the baseline risk mapping cannot be weakened.

## Phase 2 API Acceptance Tests

Phase 2 must include tests for:

- Organization creation.
- Application creation.
- Duplicate application name inside same organization.
- API key creation.
- API key revocation.
- API key authentication success.
- Invalid API key rejection.
- Revoked API key rejection.
- Application and organization mismatch rejection.


Additional Phase 2 acceptance tests: missing/malformed credentials, expiration, missing scope, inactive tenants/applications, admin role enforcement, cross-tenant reads and writes, one-time key disclosure, hash-only storage, pagination boundaries, and idempotent revocation.
