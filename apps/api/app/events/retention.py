"""Operator-only retention; each deletion batch commits independently."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app.models import SecurityEvent


@dataclass(frozen=True)
class RetentionPlan:
    cutoff: datetime
    organization_id: UUID | None = None
    batch_size: int = 1000
    max_batches: int = 100

    def __post_init__(self):
        if self.cutoff.tzinfo is None or self.cutoff.utcoffset() is None:
            raise ValueError("Retention cutoff must be timezone-aware.")
        if not 1 <= self.batch_size <= 10000 or not 1 <= self.max_batches <= 1000:
            raise ValueError("Invalid retention batch bounds.")

    @classmethod
    def for_days(cls, days=90, **kwargs):
        if not 1 <= days <= 36500:
            raise ValueError("Retention days must be between 1 and 36500.")
        return cls(datetime.now(timezone.utc) - timedelta(days=days), **kwargs)

    def conditions(self):
        conditions = [SecurityEvent.created_at < self.cutoff]
        if self.organization_id is not None:
            conditions.append(SecurityEvent.organization_id == self.organization_id)
        return conditions


def preview(engine, plan: RetentionPlan) -> int:
    """Point-in-time eligible count; does not reserve rows or promise a delete count."""
    with Session(engine) as session, session.begin():
        session.execute(text("SET LOCAL statement_timeout = '10s'"))
        return session.scalar(select(func.count()).select_from(SecurityEvent).where(*plan.conditions()))


def delete_batch(session: Session, plan: RetentionPlan) -> int:
    """Caller owns transaction. Locked rows are skipped for concurrent workers."""
    session.execute(text("SET LOCAL statement_timeout = '10s'"))
    session.execute(text("SET LOCAL lock_timeout = '1s'"))
    candidates = (select(SecurityEvent.id).where(*plan.conditions())
                  .order_by(SecurityEvent.created_at, SecurityEvent.id)
                  .limit(plan.batch_size).with_for_update(skip_locked=True).cte("expired_events"))
    deleted = session.execute(delete(SecurityEvent).where(SecurityEvent.id.in_(select(candidates.c.id)))
                              .returning(SecurityEvent.id)).all()
    return len(deleted)


def cleanup(engine, plan: RetentionPlan) -> int:
    """Return committed deletions only. Errors propagate; earlier batches stay committed."""
    total = 0
    for _ in range(plan.max_batches):
        with Session(engine) as session, session.begin():
            count = delete_batch(session, plan)
        total += count
        if count == 0:
            break
    return total
