"""Pure, deterministic policy evaluation. Exceptions never authorize forwarding."""
from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from app.detection import MatchedRule, ScanResult
from app.detection.rules import RULES, RULESET_VERSION
from app.detection.scanner import SEVERITY_SCORES, risk_level

CATEGORIES = frozenset(rule.category for rule in RULES)


class PolicyEvaluationError(ValueError):
    pass


class HardDeny(str, Enum):
    INVALID_KEY = "invalid_api_key"
    REVOKED_KEY = "revoked_api_key"
    EXPIRED_KEY = "expired_api_key"
    MISSING_SCOPE = "missing_scope"
    TENANT_MISMATCH = "tenant_mismatch"
    UNAUTHORIZED_TOOL = "unauthorized_tool"


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    id: UUID | None = None
    version: int = 0
    blocked_categories: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: str
    reason: str
    policy_id: UUID | None
    policy_version: int

    @property
    def can_forward(self) -> bool:
        return self.decision == "allow"


def evaluate(scan_result: ScanResult | None, policy: PolicySnapshot = PolicySnapshot(),
             hard_denies: tuple[HardDeny, ...] = ()) -> PolicyDecision:
    """Trusted callers supply hard denials; public request data must never do so."""
    try:
        if not isinstance(policy, PolicySnapshot) or type(policy.version) is not int:
            raise ValueError
        if ((policy.id is None and policy.version != 0)
                or (policy.id is not None and (not isinstance(policy.id, UUID) or policy.version < 1))
                or not isinstance(policy.blocked_categories, tuple)
                or any(category not in CATEGORIES for category in policy.blocked_categories)
                or len(set(policy.blocked_categories)) != len(policy.blocked_categories)):
            raise ValueError
        if not isinstance(hard_denies, tuple) or any(not isinstance(item, HardDeny) for item in hard_denies):
            raise ValueError
        if hard_denies:
            return PolicyDecision("block", "A mandatory security restriction denied the request.", policy.id, policy.version)
        if not isinstance(scan_result, ScanResult):
            raise ValueError
        if (type(scan_result.risk_score) not in (float, int)
                or risk_level(scan_result.risk_score) != scan_result.risk_level
                or not isinstance(scan_result.categories, tuple)
                or not isinstance(scan_result.matched_rules, tuple)
                or scan_result.ruleset_version != RULESET_VERSION
                or len(set(scan_result.categories)) != len(scan_result.categories)
                or any(not isinstance(rule, MatchedRule) for rule in scan_result.matched_rules)
                or len({rule.id for rule in scan_result.matched_rules}) != len(scan_result.matched_rules)
                or any(not any(rule.id == registered.id and rule.category == registered.category
                               and rule.severity == registered.severity for registered in RULES)
                       for rule in scan_result.matched_rules)
                or set(scan_result.categories) != {rule.category for rule in scan_result.matched_rules}
                or any(category not in CATEGORIES for category in scan_result.categories)
                or scan_result.risk_score != max(
                    (SEVERITY_SCORES[rule.severity] for rule in scan_result.matched_rules), default=0.0)):
            raise ValueError
        if set(scan_result.categories).intersection(policy.blocked_categories):
            decision, reason = "block", "An application policy blocks a detected category."
        else:
            decision = {"low": "allow", "medium": "review", "high": "block", "critical": "block"}[scan_result.risk_level]
            reason = "The default risk mapping determined the decision."
        return PolicyDecision(decision, reason, policy.id, policy.version)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise PolicyEvaluationError("Policy evaluation could not be completed.") from exc
