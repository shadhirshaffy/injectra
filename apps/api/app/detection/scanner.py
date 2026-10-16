"""Pure scanner: no persistence, logging, settings, or policy decisions."""
import math
from types import MappingProxyType
import unicodedata

from .rules import CONTENT_TYPES, RULES, RULESET_VERSION
from .types import ContentType, MatchedRule, ScanResult, ScanValidationError, Severity

SEVERITY_SCORES = MappingProxyType({"low": 0.10, "medium": 0.35, "high": 0.65, "critical": 0.90})


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).casefold()
    # Cf includes zero-width joiners, word joiners, BOM, and bidi format controls.
    text = "".join(char for char in text if unicodedata.category(char) != "Cf")
    return " ".join(text.split())


def risk_level(score: float) -> Severity:
    if not math.isfinite(score) or not 0 <= score <= 1:
        raise ValueError("Risk score must be finite and between zero and one.")
    if score < 0.25:
        return "low"
    if score < 0.50:
        return "medium"
    if score < 0.80:
        return "high"
    return "critical"


def scan(input_text: str, content_type: ContentType = "prompt") -> ScanResult:
    if not isinstance(input_text, str) or not 1 <= len(input_text) <= 20_000:
        raise ScanValidationError("Input must be text containing 1 to 20000 characters.")
    if not isinstance(content_type, str) or content_type not in CONTENT_TYPES:
        raise ScanValidationError("Unsupported content type.")
    normalized = normalize(input_text)
    if not normalized:
        raise ScanValidationError("Input must contain visible text.")
    # Strip only boundary whitespace; normalization already inspects that view.
    # Avoid rescanning identical views of ordinary ASCII input.
    representations = tuple(dict.fromkeys((input_text.strip(), normalized)))
    found = tuple(sorted(
        (rule for rule in RULES if content_type in rule.content_types
         and any(pattern.search(text) for pattern in rule.patterns for text in representations)),
        key=lambda rule: rule.id,
    ))
    score = max((SEVERITY_SCORES[rule.severity] for rule in found), default=0.0)
    return ScanResult(
        ruleset_version=RULESET_VERSION,
        risk_score=score,
        risk_level=risk_level(score),
        categories=tuple(sorted({rule.category for rule in found})),
        matched_rules=tuple(MatchedRule(rule.id, rule.name, rule.category, rule.severity) for rule in found),
        reason=" ".join(rule.description for rule in found) if found else "No supported injection patterns matched.",
    )
