from datetime import datetime, timezone
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class NamedCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=150)


class ApplicationCreate(NamedCreate):
    organization_id: UUID


class KeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organization_id: UUID
    application_id: UUID
    scopes: list[str] = Field(default_factory=lambda: ["gateway:scan"], min_length=1)
    expires_at: AwareDatetime | None = None

    @field_validator("scopes")
    @classmethod
    def supported_scopes(cls, value):
        if set(value) != {"gateway:scan"} or len(value) != 1:
            raise ValueError("Only gateway:scan is supported")
        return value

    @field_validator("expires_at")
    @classmethod
    def future_expiration(cls, value):
        if value is not None and value <= datetime.now(timezone.utc):
            raise ValueError("Expiration must be in the future")
        return value.astimezone(timezone.utc) if value is not None else None


class OrganizationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    status: str
    created_at: datetime


class ApplicationRead(OrganizationRead):
    organization_id: UUID


class KeyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    organization_id: UUID
    application_id: UUID
    key_prefix: str
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class KeyCreated(KeyRead):
    key: str


class KeyRevoked(BaseModel):
    id: UUID
    revoked_at: datetime


class OrganizationPage(BaseModel):
    items: list[OrganizationRead]
    next_cursor: str | None


class ApplicationPage(BaseModel):
    items: list[ApplicationRead]
    next_cursor: str | None


class KeyPage(BaseModel):
    items: list[KeyRead]
    next_cursor: str | None
