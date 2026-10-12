
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.base import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    __table_args__ = (
        UniqueConstraint(
            "key_prefix",
            name="uq_api_key_prefix",
        ),
        ForeignKeyConstraint(
            ["application_id", "organization_id"],
            ["applications.id", "applications.organization_id"],
            name="fk_api_key_application_tenant",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )

    application_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    key_prefix: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    key_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    scopes: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
