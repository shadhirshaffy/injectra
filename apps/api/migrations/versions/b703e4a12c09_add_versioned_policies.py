"""Add tenant-owned policies and immutable versions.

Revision ID: b703e4a12c09
Revises: 80d0d704fc81
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "b703e4a12c09"
down_revision = "80d0d704fc81"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("policies",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("application_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("rules", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["application_id", "organization_id"], ["applications.id", "applications.organization_id"], ondelete="CASCADE"),
        sa.UniqueConstraint("application_id", "organization_id", name="uq_policy_application_org"),
        sa.CheckConstraint("current_version >= 1", name="ck_policy_current_version"),
        sa.CheckConstraint("status = 'active'", name="ck_policy_status"),
    )
    op.create_index("ix_policies_organization_id", "policies", ["organization_id"])
    op.create_index("ix_policy_active_application", "policies", ["application_id"], unique=True, postgresql_where=sa.text("status = 'active'"))
    op.create_table("policy_versions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("rules", postgresql.JSONB(), nullable=False),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("policy_id", "version", name="uq_policy_version"),
        sa.CheckConstraint("version >= 1", name="ck_policy_version_positive"),
    )
    op.create_index("ix_policy_versions_created_by_user_id", "policy_versions", ["created_by_user_id"])
    op.create_index("ix_policy_versions_history", "policy_versions", ["policy_id", "created_at", "id"])
    op.execute("""CREATE FUNCTION reject_policy_version_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'Policy versions are immutable' USING ERRCODE = '23514';
        END; $$""")
    op.execute("""CREATE TRIGGER immutable_policy_versions BEFORE UPDATE OR DELETE
        ON policy_versions FOR EACH ROW EXECUTE FUNCTION reject_policy_version_mutation()""")


def downgrade():
    op.execute("DROP TRIGGER immutable_policy_versions ON policy_versions")
    op.execute("DROP FUNCTION reject_policy_version_mutation()")
    op.drop_table("policy_versions")
    op.drop_table("policies")
