"""Dependency-free, immutable detection contracts."""
from dataclasses import dataclass
from typing import Literal

ContentType = Literal["prompt", "rag_context", "tool_output", "response"]
Severity = Literal["low", "medium", "high", "critical"]


class ScanValidationError(ValueError):
    """The caller supplied input outside the scanner contract."""


@dataclass(frozen=True, slots=True)
class MatchedRule:
    id: str
    name: str
    category: str
    severity: Severity


@dataclass(frozen=True, slots=True)
class ScanResult:
    ruleset_version: str
    risk_score: float
    risk_level: Severity
    categories: tuple[str, ...]
    matched_rules: tuple[MatchedRule, ...]
    reason: str
