# Phase 2 Backend Foundation

## Implemented

- Shared request IDs, safe JSON errors, no-store responses, and transactional SQLAlchemy session dependencies.
- Organization creation with atomic owner membership, organization reads/lists, application creation/reads/lists, and tenant-scoped cursor pagination.
- Owner/admin role checks for application writes and API key creation/listing/revocation. Nonmembers receive 404; members without the required role receive 403.
- Cryptographic API keys with 256-bit secrets, random lookup prefixes, HMAC-SHA-256 storage, collision retries, one-time disclosure, and idempotent revocation.
- Reusable gateway authentication dependency checks hash, revocation, expiration, active tenant/application, and required scope. It does not add a scan route before detection and policy are ready.
- PostgreSQL integration tests apply the actual migration in a new randomly named private schema and run Alembic's schema drift check. Every test rolls back its data; schema teardown removes only that generated test schema.
- CI runs the backend tests with a dedicated PostgreSQL service.

## Management Authentication Boundary

Production management authentication is not yet implemented. Management endpoints reject requests by default. The replaceable `get_admin` dependency currently offers only an explicitly enabled local development adapter. Customer application keys cannot authenticate management requests.

For local development, copy `infrastructure/.env.example` to `infrastructure/.env` if no local file exists; preserve existing credentials. Set:

```dotenv
APP_ENVIRONMENT=development
DEV_ADMIN_ENABLED=true
DEV_ADMIN_SUBJECT=local-admin
DEV_ADMIN_TOKEN=<independent-random-secret-at-least-32-characters>
API_KEY_PEPPER=<independent-random-secret-at-least-32-characters>
```

Generate each secret independently with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Keep the pepper stable: changing it invalidates existing keys. Never commit the local environment file.

From `apps/api`, with its virtual environment activated:

```powershell
docker compose --env-file ../../infrastructure/.env -f ../../infrastructure/compose.yaml up -d
python -m alembic upgrade head
python -m app.cli create-local-admin
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

The adapter requires a loopback client, development environment, an active database user matching the configured subject, and an exact bearer token. It never takes a user ID or subject from client headers or body fields. Do not expose this development server through a reverse proxy or public tunnel. Verified user sessions/JWTs must replace this adapter before deployment.

Open `/docs` and use Authorize with `DEV_ADMIN_TOKEN` to create an organization, create an application under it, and create an API key. Key listing returns metadata only. Only `gateway:scan` is currently issued; other scopes remain reserved.

## Verification

Run `python -m pytest` from `apps/api` while local PostgreSQL is healthy. Tests require schema creation privileges in the configured database; the Compose development database and CI service provide these. The test suite never migrates or deletes the public schema.

The existing PostgreSQL schema is unchanged. Fresh migration application and Alembic drift detection are exercised by the integration test fixture. Existing public data is left intact.

Local verification on 2026-10-15 (Asia/Colombo): 29 backend tests passed; frontend lint/build, Compose configuration validation, and Git whitespace checks passed. The existing AnyIO BlockingPortal dependency deprecation warning remains. Hosted CI has not yet been run for this commit.

## Next

Phase 3 implements rule-based detection with known attack prompts, benign regressions, and explicit scoring tests. Policy evaluation and event persistence follow before exposing the end-to-end gateway scan. Production management identity integration remains a deployment prerequisite.
