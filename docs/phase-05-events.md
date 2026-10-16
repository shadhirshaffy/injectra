# Phase 5 — Security Event Persistence

## Delivered boundary

Adds PostgreSQL security events, an internal scan-event persistence service, and
tenant-authorized management read APIs. No public event ingestion or gateway scan
endpoint is exposed. Provider invocation, authentication-failure event producers,
rate-limit producers, and frontend screens remain future work. Production
management authentication is still a prerequisite for deployment.

`record_scan_event(session, identity, request_id, input_text, scan_result,
policy_decision, content_type="prompt", metadata=None)` accepts trusted
`GatewayIdentity` context and the server-generated UUID request ID. It verifies
key/application/organization ownership, recomputes scanner evidence, and validates
the decision against its referenced historical policy snapshot. Historical policy
versions are supported when a concurrent edit occurs after evaluation. The
built-in default is represented by null policy ID/version 0. The service supports
completed prompt/RAG/tool-output/response scans; hard-denied authentication events
are not accepted through this scan-specific helper.

The helper adds and flushes the event without committing the caller's transaction.
Persistence, identity, evidence, or policy-reference failures return a safe
`503 service_unavailable`. Invalid metadata returns `422 validation_error`.
Callers must rollback on error and **commit successfully before returning a scan
decision**. A flush is not durable persistence. There is no fail-open path or
fallback event ID; commit-time errors must also produce 503 in Phase 6.

## Privacy and integrity

- Raw input and redacted excerpts are disabled. A database check enforces null
  `redacted_input`; full input text is never a column in this milestone.
- SHA-256 of the original UTF-8 input is stored only for correlation. Hashes are
  not anonymization and may be guessable for common prompts. They are excluded
  from the management API along with key IDs and redacted content.
- Metadata must be a JSON object of at most 4 KiB of UTF-8 JSON. Only `source`
  values `chat`, `api`, `rag`, `tool`, and `batch` survive. Unknown fields and
  source values are dropped. Customer user IDs, credentials, arbitrary labels,
  and nested customer metadata are not persisted.
- Reasons and matched rules originate from code-owned scanner/policy descriptions.
  Request bodies, exceptions, prompts, and credentials are never used as reasons.
- Composite foreign keys enforce application/organization ownership for events,
  API keys, and policies. Another FK pins configured events to an existing policy
  version. Database checks constrain scores, decisions, risk/content/event types,
  and default/configured policy reference consistency.
- Foreign keys use RESTRICT to preserve event attribution. No event update/delete
  API is provided. Existing API-key revocation continues to work because keys are
  retained rather than deleted.

## Management API

`GET /api/v1/security-events` returns `{ "items": [], "next_cursor": null }`.
It requires the existing management identity; application API keys are not
management credentials. Results are limited to active organizations where the
current user is a member, including member-role users. An omitted organization
filter means all currently authorized organizations, never all tenants.

Supported filters:

| Filter | Behavior |
| --- | --- |
| organization_id | Must be a visible organization; otherwise 404 |
| application_id | Must be visible and match any organization filter |
| decision | allow, block, review, restrict |
| risk_level | low, medium, high, critical |
| category | One known scanner category |
| from / to | Inclusive, timezone-aware timestamps; from must not exceed to |
| limit | 1–100, default 50 |
| cursor | Existing opaque cursor contract, bound to actor and all filters |

Ordering is `created_at DESC, id DESC`. Permission filters are reapplied on every
page. Cursors cannot be reused with different filters. Invalid filters return
422; missing authentication returns 401. Database failures return safe 503 errors.

`GET /api/v1/security-events/{event_id}` returns one visible event or 404 for both
foreign and nonexistent IDs. Historical events remain readable for inactive
applications while their organization remains active and membership is valid.

Each item contains event ID, organization/application IDs, request ID, event and
content types, decision, risk level/score, categories, matched-rule metadata,
static reason, ruleset version, evaluated policy ID/version, sanitized `metadata`,
and UTC creation timestamp. No raw input, input hash, key secret/hash/prefix, or
provider credentials are returned.

## Migration and verification

Migration `c815f6b23d10` adds event storage, ownership uniqueness constraints on
keys/policies, composite foreign keys, tenant/time pagination indexes, request
lookup indexes, and a GIN category-filter index. Existing identity and policy
rows remain intact. Apply migrations before using the event service or APIs:

```powershell
cd apps/api
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m pytest
```

The migration is tested in disposable PostgreSQL schemas, including schema drift
checks, full downgrade/re-upgrade, numeric/status constraints, ownership checks,
and persistence across committed sessions. The local public application schema
has not been automatically migrated. Migration downgrade deletes event data;
prefer reverting the application while preserving tables until a backup and
data-loss plan is approved.

Before production, establish tenant retention/deletion requirements and an
audited retention job. There is no scheduled deletion or raw capture opt-in in
Phase 5. Database operators remain trusted; this is not tamper-proof audit storage.

Local verification on 2026-10-16 (Asia/Colombo): 325 backend tests passed. The
pre-existing AnyIO BlockingPortal deprecation warning remains. Hosted CI results
are reported separately in the pull request.

## Phase 6 handoff

The public scan route must authenticate first, derive tenant identity from the
verified key, validate input, scan, evaluate policy, persist the event, and commit
before returning its decision and event ID. Reuse the canonical middleware request
ID. Block and review are completed inspections with HTTP 200, but neither permits
LLM forwarding. Never attribute authentication failures to an unverified prefix;
use separate sanitized operational logs until a verified event producer exists.
