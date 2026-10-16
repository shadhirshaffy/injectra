import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import CheckConstraint, DateTime, ForeignKeyConstraint, Index, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        ForeignKeyConstraint(["application_id", "organization_id"], ["applications.id", "applications.organization_id"], ondelete="RESTRICT"),
        ForeignKeyConstraint(["api_key_id", "application_id", "organization_id"], ["api_keys.id", "api_keys.application_id", "api_keys.organization_id"], ondelete="RESTRICT"),
        ForeignKeyConstraint(["policy_id", "application_id", "organization_id"], ["policies.id", "policies.application_id", "policies.organization_id"], ondelete="RESTRICT"),
        ForeignKeyConstraint(["policy_id", "policy_version"], ["policy_versions.policy_id", "policy_versions.version"], ondelete="RESTRICT"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="ck_event_score"),
        CheckConstraint("decision IN ('allow','block','review','restrict')", name="ck_event_decision"),
        CheckConstraint("risk_level IN ('low','medium','high','critical')", name="ck_event_risk"),
        CheckConstraint("event_type IN ('prompt_scan','response_scan','gateway_invoke','auth_failure','policy_block','rate_limit')", name="ck_event_type"),
        CheckConstraint("content_type IN ('prompt','rag_context','tool_output','response')", name="ck_event_content_type"),
        CheckConstraint("(policy_id IS NULL AND policy_version = 0) OR (policy_id IS NOT NULL AND policy_version >= 1)", name="ck_event_policy_reference"),
        CheckConstraint("redacted_input IS NULL", name="ck_event_no_content"),
        Index("ix_events_org_created", "organization_id", "created_at", "id"),
        Index("ix_events_app_created", "application_id", "created_at", "id"),
        Index("ix_events_key_owner", "api_key_id", "application_id", "organization_id"),
        Index("ix_events_policy_version", "policy_id", "policy_version"),
        Index("ix_events_policy_owner", "policy_id", "application_id", "organization_id"),
        Index("ix_events_request", "request_id"),
        Index("ix_events_categories", "categories", postgresql_using="gin"),
    )
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)
    content_type: Mapped[str] = mapped_column(String(20), nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 4), nullable=False)
    categories: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    matched_rules: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    ruleset_version: Mapped[str] = mapped_column(String(30), nullable=False)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    redacted_input: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
