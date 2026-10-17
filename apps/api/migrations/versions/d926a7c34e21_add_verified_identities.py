"""Scope identities by issuer and add organization invitations.

Revision ID: d926a7c34e21
Revises: c815f6b23d10
"""
from alembic import op
import sqlalchemy as sa

revision = "d926a7c34e21"
down_revision = "c815f6b23d10"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("identity_issuer", sa.String(255), nullable=False, server_default=sa.text("'local-development'")))
    op.drop_constraint("users_identity_subject_key", "users", type_="unique")
    op.create_unique_constraint("uq_user_identity", "users", ["identity_issuer", "identity_subject"])
    # Preserve legacy read-only memberships using the documented canonical role.
    op.execute("UPDATE memberships SET role = 'developer' WHERE role = 'member'")
    op.create_table("organization_invitations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("role", sa.String(30), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=False),
        sa.Column("accepted_by_user_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("token_hash"),
        sa.CheckConstraint("role IN ('admin','developer')", name="ck_invitation_role"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["accepted_by_user_id"], ["users.id"], ondelete="RESTRICT"),
    )
    op.create_index("ix_organization_invitations_organization_id", "organization_invitations", ["organization_id"])
    op.create_index("ix_organization_invitations_created_by_user_id", "organization_invitations", ["created_by_user_id"])
    op.create_index("ix_organization_invitations_accepted_by_user_id", "organization_invitations", ["accepted_by_user_id"])


def downgrade():
    # Fails safely if subjects collide across issuers; never merge user accounts.
    op.create_unique_constraint("users_identity_subject_key", "users", ["identity_subject"])
    op.drop_table("organization_invitations")
    op.drop_constraint("uq_user_identity", "users", type_="unique")
    op.drop_column("users", "identity_issuer")
