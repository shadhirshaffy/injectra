import json
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator

from app.detection import ContentType, MatchedRule
from app.detection.scanner import normalize
from app.detection.types import Severity


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input: str = Field(strict=True, min_length=1, max_length=20000)
    content_type: ContentType = "prompt"
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("input")
    @classmethod
    def visible_input(cls, value):
        if not normalize(value):
            raise ValueError("Visible input required")
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise ValueError("Valid UTF-8 input required") from exc
        return value

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(cls, value):
        try:
            if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 4096:
                raise ValueError("Metadata exceeds 4 KiB")
        except (UnicodeError, TypeError, OverflowError, RecursionError) as exc:
            raise ValueError("Invalid JSON metadata") from exc
        return value


class ScanResponse(BaseModel):
    request_id: UUID
    organization_id: UUID
    application_id: UUID
    decision: Literal["allow", "block", "review", "restrict"]
    risk_level: Severity
    risk_score: float
    categories: list[str]
    matched_rules: list[MatchedRule]
    reason: str
    event_id: UUID
    ruleset_version: str
    policy_id: UUID | None
    policy_version: int
