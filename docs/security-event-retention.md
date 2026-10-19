# Security-event retention

Operator-only cleanup defaults to 90 days. This is an operational default that
must be reviewed against your organization's retention requirements before use.
No HTTP deletion endpoint or automatic schedule is installed. Scan admission and
event persistence remain independent of cleanup availability.

After deploying, run `python -m alembic upgrade head` from `apps/api`.
The migration adds `(created_at, id)` for global chronological cleanup. Creating
the index takes a table lock: schedule the migration during a maintenance window
for a large populated table. Downgrade removes only the index; deleted events
cannot be restored by a migration rollback.

From `apps/api`, with the normal database environment configured:

```powershell
python -m app.cli cleanup-security-events --organization-id <organization-uuid>
python -m app.cli cleanup-security-events --all-organizations --retention-days 90
# Explicitly authorized deletion, after reviewing a preview and backups:
python -m app.cli cleanup-security-events --organization-id <organization-uuid> --execute --batch-size 1000 --max-batches 100
```

Preview is the default and performs no deletion. Both preview and execution
require an explicit tenant scope or `--all-organizations`. The database credential
is the operator authority; management JWTs and API keys cannot invoke cleanup.
Use a restricted operational database account and protect its credentials.

Each invocation pins a UTC cutoff. Events strictly older than that cutoff qualify;
events exactly at the cutoff remain. Preview counts are point-in-time estimates,
not reservations: a later invocation computes a new cutoff and concurrent writes
or cleanup can change the count. All decisions, including blocks, expire equally.
There are no per-tenant custom periods or legal holds in this version. Do not
execute for tenants requiring preservation until an appropriate hold mechanism
is available.

Execution selects oldest rows with `FOR UPDATE SKIP LOCKED`, then deletes only
those IDs in the same transaction. Each batch commits separately, limits are
1–10,000 rows and 1–1,000 batches, and every statement has a 10-second timeout
with a 1-second lock timeout. Concurrent workers skip reserved rows. An empty
batch does not prove completion while other transactions hold locks. Repeat
preview and bounded execution as necessary. Errors propagate with nonzero exit;
previously committed batches remain deleted. Retry is safe. No content, hashes,
event IDs, credentials, or matched excerpts are printed by the cleanup code.

Cleanup deletes security events only. Organizations, applications, API keys,
policies and immutable policy versions remain. API pagination may naturally omit
expired rows; client cursors continue using timestamp/ID ordering. Backups and
replicas have independent retention and must be managed separately. Ordinary
PostgreSQL autovacuum reclaims dead tuples; this command does not run VACUUM FULL.

Operators may schedule the bounded command using their deployment scheduler
after reviewing retention requirements. Capture exit status, committed count and
cutoff in restricted operational logs; investigate failures and growing backlog.
No durable deletion audit record is added by this milestone. A failed command may
have partially completed, so reconcile with a new preview rather than treating
its absence of a final count as zero deletions.

Verification: `python -m pytest tests/test_retention.py`, followed by
`python -m pytest`. Tests use disposable PostgreSQL schemas, not application data.
