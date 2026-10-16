from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    id: UUID
    organization_id: UUID
    application_id: UUID
    request_id: UUID
    event_type: str
    content_type: str
    decision: str
    risk_level: str
    risk_score: float
    categories: list[str]
    matched_rules: list[dict]
    reason: str
    ruleset_version: str
    policy_id: UUID | None
    policy_version: int
    metadata: dict = Field(validation_alias="event_metadata")
    created_at: datetime


class SecurityEventPage(BaseModel):
    items: list[SecurityEventRead]
    next_cursor: str | None
