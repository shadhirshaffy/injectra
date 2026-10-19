from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.events.retention import RetentionPlan, delete_batch, preview, cleanup
from app.models import APIKey, Application, Organization, SecurityEvent
from test_security_events import event_for


def test_exclusive_boundary_tenant_scope_and_privacy(client, db):
    key, old = event_for(client, db)
    _, other = event_for(client, db)
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    old.created_at = cutoff - timedelta(microseconds=1)
    other.created_at = old.created_at
    _, boundary = event_for(client, db)
    boundary.organization_id = old.organization_id
    boundary.application_id = old.application_id
    boundary.api_key_id = old.api_key_id
    boundary.created_at = cutoff
    db.flush()
    plan = RetentionPlan(cutoff, old.organization_id)
    assert delete_batch(db, plan) == 1
    assert db.scalar(select(SecurityEvent.id).where(SecurityEvent.id == old.id)) is None
    assert db.scalar(select(SecurityEvent.id).where(SecurityEvent.id == other.id)) == other.id
    assert db.scalar(select(SecurityEvent.id).where(SecurityEvent.id == boundary.id)) == boundary.id
    assert db.get(APIKey, old.api_key_id) is not None
    assert db.get(Organization, old.organization_id) is not None


def test_batch_bounds_and_rollback(client, db):
    _, event = event_for(client, db)
    event.created_at = datetime.now(timezone.utc) - timedelta(days=100)
    db.flush()
    event_id = event.id
    plan = RetentionPlan.for_days(90, organization_id=event.organization_id, batch_size=1, max_batches=1)
    nested = db.begin_nested()
    assert delete_batch(db, plan) == 1
    nested.rollback()
    assert db.scalar(select(SecurityEvent.id).where(SecurityEvent.id == event_id)) == event_id


def test_empty_preview_and_cleanup(migrated_engine):
    plan = RetentionPlan.for_days(90, organization_id=uuid4())
    assert preview(migrated_engine, plan) == 0
    assert cleanup(migrated_engine, plan) == 0


def test_committed_batches_preview_and_concurrent_locks(migrated_engine):
    # Committed rows live only inside the fixture's disposable schema.
    with Session(migrated_engine) as session, session.begin():
        org = Organization(name="retention-test")
        session.add(org)
        session.flush()
        application = Application(organization_id=org.id, name="retention-test")
        session.add(application)
        session.flush()
        org_id = org.id
        for _ in range(3):
            session.add(SecurityEvent(organization_id=org.id, application_id=application.id,
                request_id=uuid4(), event_type="prompt_scan", content_type="prompt", decision="allow",
                risk_level="low", risk_score=0, reason="No supported patterns matched.",
                ruleset_version="1.0.0", policy_version=0, input_hash="0" * 64,
                created_at=datetime.now(timezone.utc) - timedelta(days=100)))
    plan = RetentionPlan.for_days(organization_id=org_id, batch_size=1, max_batches=1)
    assert preview(migrated_engine, plan) == 3
    assert preview(migrated_engine, plan) == 3  # preview has no side effects
    with Session(migrated_engine) as worker, worker.begin():
        assert delete_batch(worker, plan) == 1  # holds one row until commit
        assert cleanup(migrated_engine, plan) == 1  # skips that lock, commits another
    assert preview(migrated_engine, plan) == 1
    assert cleanup(migrated_engine, plan) == 1
    assert preview(migrated_engine, plan) == 0


def test_cli_requires_scope_and_defaults_to_preview(monkeypatch, capsys):
    from app import cli
    from app.events import retention
    monkeypatch.setattr("sys.argv", ["cli", "cleanup-security-events"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    calls = []
    monkeypatch.setattr(retention, "preview", lambda engine, plan: calls.append(plan) or 7)
    monkeypatch.setattr(retention, "cleanup", lambda *args: pytest.fail("Unexpected deletion"))
    monkeypatch.setattr("sys.argv", ["cli", "cleanup-security-events", "--all-organizations"])
    cli.main()
    assert len(calls) == 1 and calls[0].organization_id is None
    assert "Dry run; eligible events: 7" in capsys.readouterr().out


@pytest.mark.parametrize("kwargs", [{"batch_size": 0}, {"batch_size": 10001},
                                   {"max_batches": 0}, {"max_batches": 1001}])
def test_invalid_bounds(kwargs):
    with pytest.raises(ValueError):
        RetentionPlan.for_days(**kwargs)


def test_invalid_cutoff_and_days():
    with pytest.raises(ValueError):
        RetentionPlan(datetime.now())
    for days in (0, -1, 36501):
        with pytest.raises(ValueError):
            RetentionPlan.for_days(days)
