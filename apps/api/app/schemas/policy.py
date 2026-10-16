from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.policy.engine import CATEGORIES


class PolicyRules(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    blocked_categories: list[str] = Field(max_length=8)

    @field_validator("blocked_categories")
    @classmethod
    def known_categories(cls, value):
        if len(value) != len(set(value)) or any(category not in CATEGORIES for category in value):
            raise ValueError("Categories must be known and unique")
        return sorted(value)


class PolicyWrite(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(default="Application policy", min_length=1, max_length=150)
    expected_version: int = Field(ge=0, strict=True)
    rules: PolicyRules


class PolicyRead(BaseModel):
    id: UUID | None
    organization_id: UUID
    application_id: UUID
    name: str
    version: int
    source: str
    rules: PolicyRules
    created_at: datetime | None
    updated_at: datetime | None


class PolicyVersionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    policy_id: UUID
    version: int
    name: str
    rules: PolicyRules
    created_by_user_id: UUID | None
    created_at: datetime


class PolicyVersionPage(BaseModel):
    items: list[PolicyVersionRead]
    next_cursor: str | None
