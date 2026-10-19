"""Index bounded chronological event cleanup.

Revision ID: ea37b8d45f32
Revises: d926a7c34e21
"""
from alembic import op

revision = "ea37b8d45f32"
down_revision = "d926a7c34e21"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("ix_events_retention", "security_events", ["created_at", "id"])


def downgrade():
    op.drop_index("ix_events_retention", table_name="security_events")
