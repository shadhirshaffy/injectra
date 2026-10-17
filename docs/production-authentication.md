# Production Authentication — Clerk

## Architecture and choice

Clerk handles sign-in and session issuance. Injectra owns organization membership
and authorization in PostgreSQL. This fits the existing React/Vite frontend and
FastAPI backend without migrating customer data or duplicating organization roles
in a second system. Clerk organization claims are not authorization inputs.

The frontend uses the official `@clerk/react` SDK. The backend uses PyJWT with
cryptography for Clerk's documented RS256/JWKS verification flow, plus explicit
issuer, audience/origin, required-claim, and token-age enforcement. A small HTTP
adapter checks live sessions through Clerk's Backend API before management writes.
This keeps the backend's token acceptance and network timeouts explicit rather
than accepting the provider SDK's broader machine-token defaults.

References: [React integration](https://clerk.com/docs/react/getting-started/quickstart),
[session token verification](https://clerk.com/docs/guides/sessions/manual-jwt-verification),
[session claims](https://clerk.com/docs/guides/sessions/session-tokens).

## Security contract

- Only RS256 JWTs from the configured HTTPS issuer are accepted. Signing keys are
  retrieved only from that issuer's `/.well-known/jwks.json`, never token URLs.
- Required claims: iss, sub, sid, exp, iat, nbf, azp. Subjects and session IDs must
  use Clerk's user_/sess_ forms. Pending sessions are denied. Lifetime is bounded
  to 120 seconds with five seconds of clock skew. Standard Clerk session tokens
  fit this bound; custom long-lived tokens are intentionally rejected.
- Authorized parties are exact frontend origins. If an Origin header is present,
  it must also equal the signed azp claim. Configure an audience to require aud;
  omit it for ordinary Clerk session tokens without a custom audience claim.
- JWKS caching is scoped by issuer, expires after five minutes, and refreshes for
  rotation. Refreshes for unknown IDs/signature mismatches are throttled to one
  per five seconds. This can briefly reject a newly rotated key; clients may retry.
  No expired-key-cache fallback occurs when the provider cannot be reached.
- All management writes require a live active session whose session ID and user
  ID match the verified token. Provider failure returns 503; revoked/inactive
  sessions return 401. No browser cookies are accepted by the API: the frontend
  supplies a Bearer session token without storing it in localStorage or URLs.
- Read requests validate short-lived tokens locally when signing keys are cached.
  Provider-side revocation can take effect on reads only when the token expires
  (at most 125 seconds with skew). Local suspension and membership removal are
  checked against PostgreSQL on each request and take effect immediately.
- HTTP calls use three-second operation timeouts, no redirects, and no inherited
  proxy credentials. Provider errors are sanitized; tokens and secret keys are
  never returned or logged. Signing-key requests contain no server secret.
- Unauthenticated access returns 401 with WWW-Authenticate: Bearer. Missing
  permissions return 403; foreign resources retain 404 behavior. Gateway API-key
  authentication is unchanged and cannot authenticate management routes.

## Organization model

Verified users are provisioned by the unique (issuer, subject) pair, initially
without any memberships. Repeated/concurrent authentication cannot create
duplicates or reactivate suspended users. Email addresses never link accounts.

| Role | Permissions |
| --- | --- |
| owner | Organization administration and existing management operations |
| admin | Application/key/policy administration; invitations and non-owner membership administration |
| developer | Organization/application/policy/event reads; no key or membership administration |

Any active verified user may create a new organization and becomes its owner,
matching the existing onboarding contract. Joining an existing organization
requires an explicit invitation. Owner membership changes and ownership transfer
are not exposed: no admin can demote or delete an owner, including the last owner.
Unknown roles are denied and excluded from organization/event listings. Legacy
`member` roles migrate to the canonical `developer` read role.

Invitations expire after seven days and contain 256 bits of randomness. Only
SHA-256 token hashes persist; the raw code is returned once at creation. Codes
are shared manually and privately; this implementation sends no email. Acceptance
requires a verified email address fetched from Clerk's authoritative user record,
an active organization, and an active inviter who still has management permission.
Tokens are single-use, revocable, and cannot change an existing member's role.
Database locks serialize acceptance and concurrent invitations for the same
organization. There is no automatic domain-based membership or owner invitation.

### Endpoints

- GET `/api/v1/me`: internal user ID and visible organization IDs/names/roles.
- POST `/api/v1/organizations/{id}/invitations`: `{ "email": "person@example.com", "role": "developer" }`; returns invitation and one-time token. Role may be admin or developer.
- GET `/api/v1/organizations/{id}/invitations`: management-only paginated metadata, without codes/hashes.
- POST `/api/v1/organizations/{id}/invitations/{invite_id}/revoke`: idempotent revocation of unaccepted invitations.
- POST `/api/v1/invitations/accept`: `{ "token": "one-time-code" }`; verified provider identity required.
- GET `/api/v1/organizations/{id}/memberships`: member-readable paginated IDs/roles.
- PATCH `/api/v1/organizations/{id}/memberships/{membership_id}`: `{ "role": "admin" }` or developer; owners cannot be changed.
- DELETE `/api/v1/organizations/{id}/memberships/{membership_id}`: removes non-owner membership; returns 204.

List endpoints use the existing limit/cursor convention (50 default, 1–100).
The frontend exposes sign-in/sign-up/sign-out, organization selection/creation,
member viewing, and invitation creation/acceptance. Membership editing and
invitation revocation are available through the API; a full administration UI is
not part of this authentication milestone. Switching users remounts workspace
state so a previous user's profile or invitation code is not reused.

## Configure later: no provider account has been created

No Clerk application or production credentials were supplied, so live provider
sign-in has not been tested or enabled. When ready:

1. Create/select your Clerk application and enable your intended sign-in methods.
   Configure verification and MFA requirements in Clerk; pending session tasks
   must complete before Injectra accepts the session.
2. Set backend values in the existing ignored `infrastructure/.env`:

```dotenv
APP_ENVIRONMENT=production
DEV_ADMIN_ENABLED=false
MANAGEMENT_AUTH_PROVIDER=clerk
CLERK_ISSUER=https://your-configured-clerk-issuer
CLERK_SECRET_KEY=<server-only-secret>
CLERK_AUTHORIZED_PARTIES=["https://app.example.com"]
# Optional only when the session token has this custom audience:
# CLERK_AUDIENCE=injectra-api
```

3. Configure `apps/web/.env.local` (ignored):

```dotenv
VITE_CLERK_PUBLISHABLE_KEY=<public-publishable-key>
VITE_API_BASE_URL=
```

Never place CLERK_SECRET_KEY in a VITE_ variable. An empty API base means the API
is reverse-proxied under the frontend origin. Development Vite proxies `/api` to
127.0.0.1:8000. For local Clerk testing use APP_ENVIRONMENT=development,
DEV_ADMIN_ENABLED=false, and authorized party `http://localhost:5173`. For a
separate production API origin, configure its HTTPS URL and the same exact frontend
origin allowlist. CORS allows Bearer headers without credentialed cookies.

4. Apply migration d926a7c34e21, then start the API and frontend. The migration has
   not been applied to your application database automatically. Keep the existing
   API_KEY_PEPPER unchanged.
5. Test real sign-up, login, logout, session revocation, MFA, and invitation
   acceptance before exposing management access publicly. Confirm hostname,
   audience if used, CORS, issuer, and key rotation with your actual instance.

## Existing user cutover and rollback

Existing users migrate to issuer `local-development`; their IDs and memberships
are preserved. Do not automatically merge email-matching accounts. To preserve an
existing local owner's access, explicitly link its internal ID to a Clerk subject
**before that Clerk identity is auto-provisioned by signing into Injectra**:

```powershell
cd apps/api
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m app.cli link-clerk-user --user-id <internal-uuid> --subject <clerk-user-id>
```

The command verifies that the provider user exists, requires an active development
user, and refuses occupied identities. It does not merge accounts or change
memberships. Operators must verify the selected IDs independently. If the Clerk
identity already has a local row, review membership transfer separately.

The development adapter remains explicitly available for loopback development
only. Startup rejects it in production or alongside Clerk. To disable management
access during rollback, set MANAGEMENT_AUTH_PROVIDER=disabled and
DEV_ADMIN_ENABLED=false. Preserve issuer mappings and membership data. Downgrade
removes invitations and issuer information and fails if subjects collide across
issuers; do not force it or merge users to make it pass.

## Validation and release limits

Tests use locally generated RSA keys and mocked provider responses, with real
PostgreSQL migration/authorization checks. They cover token forgery/expiry,
issuer/origin/audience, rotation, suspension, provider failures, invitation email
binding/replay/expiry/revocation, unknown roles, owner protection, explicit linking,
and migration preservation. Existing gateway and policy tests remain in CI.

Live Clerk flows remain a deployment validation step until credentials are
configured. Provider billing, regional requirements, abuse/rate limiting,
operational identity audit records, retention, and enterprise SSO requirements
must be addressed before a production launch.

Local verification on 2026-10-17 (Asia/Colombo): 406 backend tests passed,
including 31 authentication/onboarding tests. Frontend lint and production build,
Compose configuration validation, and whitespace checks passed. The existing
AnyIO BlockingPortal deprecation warning remains. Live Clerk sign-in was not run.
