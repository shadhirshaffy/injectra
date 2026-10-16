"""Reviewed English command signatures. Update version for any behavior change.

Patterns intentionally require command-like clauses rather than keyword presence.
All repetition has explicit bounds; no input can supply an expression.
"""
from dataclasses import dataclass
import re
from typing import Pattern

from .types import ContentType, Severity

RULESET_VERSION = "1.0.0"
CONTENT_TYPES: tuple[ContentType, ...] = ("prompt", "rag_context", "tool_output", "response")


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    category: str
    severity: Severity
    description: str
    content_types: tuple[ContentType, ...]
    patterns: tuple[Pattern[str], ...]


# Start of input, line, or sentence; optional politeness is tightly bounded.
# Quoted examples and educational framing are not treated as direct commands.
_START = r"(?:\A|[\n.!?;][ \t]{0,8})(?:please[ \t]{1,4})?"


def _rule(category: str, name: str, severity: Severity, description: str, *patterns: str) -> Rule:
    return Rule(
        f"rule_{category}_001", name, category, severity, description,
        CONTENT_TYPES, tuple(re.compile(_START + pattern, re.IGNORECASE) for pattern in patterns),
    )


RULES: tuple[Rule, ...] = (
    _rule("instruction_override", "Instruction override attempt", "high",
          "Direct instructions attempt to override prior instructions.",
          r"(?:ignore|disregard|forget|override)\s{1,8}(?:all\s{1,8})?(?:previous|prior|earlier)\s{1,8}(?:instructions|directives|rules)\b"),
    _rule("system_prompt_extraction", "System prompt extraction attempt", "high",
          "Direct instructions request hidden system instructions.",
          r"(?:reveal|show|print|repeat|output|disclose)\s{1,8}(?:your|the)\s{1,8}(?:hidden\s{1,8})?(?:system|developer)\s{1,8}(?:prompt|instructions)\b"),
    _rule("policy_bypass", "Safety policy bypass attempt", "high",
          "Direct instructions attempt to disable safety controls.",
          r"(?:disable|bypass|ignore|remove|suspend)\s{1,8}(?:(?:all|your|the)\s{1,8})?(?:safety|security)\s{1,8}(?:filters|checks|restrictions|policies|guardrails)\b"),
    _rule("role_manipulation", "Privileged role manipulation", "high",
          "Direct instructions claim a privileged or unrestricted assistant role.",
          r"(?:act|behave)\s{1,8}as\s{1,8}(?:an?\s{1,8})?(?:unrestricted|unfiltered|administrator|system)\s{1,8}(?:assistant|agent|model)\b",
          r"you\s{1,8}are\s{1,8}now\s{1,8}(?:an?\s{1,8})?(?:unrestricted|unfiltered|administrator|system)\s{1,8}(?:assistant|agent|model)\b"),
    _rule("data_exfiltration", "Secret exfiltration instruction", "critical",
          "Direct instructions request transmission of sensitive data.",
          r"(?:send|upload|transmit|post|forward)\s{1,8}(?:(?:all|the|your)\s{1,8})?(?:api\s{1,8}keys|passwords|credentials|secrets|access\s{1,8}tokens)\s{1,8}to\s{1,8}(?:https?://|an?\s{1,8}external\s{1,8}(?:server|endpoint))"),
    _rule("tool_abuse", "Unauthorized tool instruction", "critical",
          "Direct instructions request destructive shell actions.",
          r"(?:run|execute|invoke)\s{1,8}(?:the\s{1,8})?(?:shell|terminal)\s{1,8}command\s{1,8}(?:to\s{1,8})?(?:delete|erase|destroy)\s{1,8}(?:all\s{1,8})?(?:files|backups|logs)\b"),
    _rule("obfuscation", "Encoded instruction execution", "medium",
          "Direct instructions request decoding and executing concealed instructions.",
          r"(?:decode|decrypt)\s{1,8}(?:this|the)\s{1,8}(?:base64|hex|encoded)\s{1,8}(?:payload|text|message)\s{1,8}and\s{1,8}(?:execute|follow|obey)\s{1,8}(?:it|its\s{1,8}instructions)\b"),
    _rule("rag_injection", "Retrieved content authority claim", "high",
          "Direct instructions promote retrieved content over trusted instructions.",
          r"(?:treat|use|accept)\s{1,8}(?:this|the)\s{1,8}(?:document|retrieved\s{1,8}context|search\s{1,8}result)\s{1,8}as\s{1,8}(?:your|the)\s{1,8}(?:new|highest[- ]priority)\s{1,8}system\s{1,8}(?:prompt|instructions)\b"),
)
