"""Add privacy-safe, tenant-owned security events.

Revision ID: c815f6b23d10
Revises: b703e4a12c09
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "c815f6b23d10"
down_revision = "b703e4a12c09"
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint("uq_api_key_owner", "api_keys", ["id", "application_id", "organization_id"])
    op.create_unique_constraint("uq_policy_owner", "policies", ["id", "application_id", "organization_id"])
    op.create_table("security_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("api_key_id", sa.UUID(), nullable=True),
        sa.Column("request_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(30), nullable=False),
        sa.Column("content_type", sa.String(20), nullable=False),
        sa.Column("decision", sa.String(20), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Numeric(5, 4), nullable=False),
        sa.Column("categories", postgresql.JSONB(), nullable=False),
        sa.Column("matched_rules", postgresql.JSONB(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("ruleset_version", sa.String(30), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("redacted_input", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["application_id", "organization_id"], ["applications.id", "applications.organization_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["api_key_id", "application_id", "organization_id"], ["api_keys.id", "api_keys.application_id", "api_keys.organization_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id", "application_id", "organization_id"], ["policies.id", "policies.application_id", "policies.organization_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id", "policy_version"], ["policy_versions.policy_id", "policy_versions.version"], ondelete="RESTRICT"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="ck_event_score"),
        sa.CheckConstraint("decision IN ('allow','block','review','restrict')", name="ck_event_decision"),
        sa.CheckConstraint("risk_level IN ('low','medium','high','critical')", name="ck_event_risk"),
        sa.CheckConstraint("event_type IN ('prompt_scan','response_scan','gateway_invoke','auth_failure','policy_block','rate_limit')", name="ck_event_type"),
        sa.CheckConstraint("content_type IN ('prompt','rag_context','tool_output','response')", name="ck_event_content_type"),
        sa.CheckConstraint("(policy_id IS NULL AND policy_version = 0) OR (policy_id IS NOT NULL AND policy_version >= 1)", name="ck_event_policy_reference"),
        sa.CheckConstraint("redacted_input IS NULL", name="ck_event_no_content"),
    )
    for name, columns in (
        ("ix_events_org_created", ["organization_id", "created_at", "id"]),
        ("ix_events_app_created", ["application_id", "created_at", "id"]),
        ("ix_events_key_owner", ["api_key_id", "application_id", "organization_id"]),
        ("ix_events_policy_version", ["policy_id", "policy_version"]),
        ("ix_events_policy_owner", ["policy_id", "application_id", "organization_id"]),
        ("ix_events_request", ["request_id"]),
    ):
        op.create_index(name, "security_events", columns)
    op.create_index("ix_events_categories", "security_events", ["categories"], postgresql_using="gin")


def downgrade():
    op.drop_table("security_events")
    op.drop_constraint("uq_policy_owner", "policies", type_="unique")
    op.drop_constraint("uq_api_key_owner", "api_keys", type_="unique")
