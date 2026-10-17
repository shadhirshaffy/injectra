# injectra
Injectra is an AI security gateway for detecting and preventing prompt injection attacks using hybrid detection, configurable guardrails, LLM protection, RAG security, and real-time threat monitoring.


## Project status

Phases 1–6 implement the backend architecture, tenant management, API keys,
deterministic detection, versioned policies, security events, and authenticated
gateway scans. Clerk management authentication and organization onboarding are
implemented; live sign-in remains disabled until a Clerk application is configured.

- [Architecture and phase handoff](docs/phase-01-architecture.md)
- [API contracts](docs/phase-01-api-design.md)
- [Data design](docs/phase-01-data-design.md)
- [Security workflows](docs/phase-01-security-workflows.md)

[Phase 2 setup and verification](docs/phase-02-backend.md)

Phase 3 adds a standalone, versioned rule-based detector with synthetic attack and
benign regression coverage. It returns evidence only; the public scan endpoint
remains deferred until policy and event persistence are integrated.

[Phase 3 detection and verification](docs/phase-03-detection.md)

Phase 4 adds deterministic policy evaluation, tenant-scoped management endpoints,
and immutable PostgreSQL policy history with fail-closed behavior.

[Phase 4 policy API, deployment, and verification](docs/phase-04-policy.md)

Phase 5 adds privacy-safe security event persistence and tenant-scoped event read
APIs with filtering and pagination.

[Phase 5 event contracts, privacy, and deployment](docs/phase-05-events.md)

Phase 6 exposes the authenticated public scan endpoint, integrating detection,
versioned policy evaluation, and committed privacy-safe events.

[Phase 6 scan API and verification](docs/phase-06-scan.md)

Management authentication now supports Clerk sessions with database-owned
organization access and verified-email invitations. Configure your Clerk instance
before enabling live sign-in.

[Authentication setup, cutover, and verification](docs/production-authentication.md)

Next: live identity configuration/validation, rate limits, retention, and
operational controls before production launch or provider forwarding.
