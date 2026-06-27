"""Explainable risk analysis for individual agent tool invocations.

The scorer is deliberately self-contained. It classifies tool capabilities with
token-aware rules, analyzes permission scope, and then evaluates compound risk
paths such as untrusted input reaching code execution or sensitive data leaving
through an external channel. It does not authorize or execute tools.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple


TOOL_RISK_SCORING_VERSION = "2.0"
_MAX_PERMISSIONS = 256
_MAX_PERMISSION_CHARS = 512


class ToolRiskTier(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ToolRiskContribution:
    indicator: str
    weight: float
    detail: str


@dataclass
class ToolInvocationRiskResult:
    tool_name: str
    risk_tier: ToolRiskTier
    score: float
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    mitre_atlas_refs: List[str] = field(default_factory=list)
    owasp_refs: List[str] = field(default_factory=list)
    scoring_version: str = TOOL_RISK_SCORING_VERSION
    capability_class: str = "unclassified"
    matched_capabilities: List[str] = field(default_factory=list)
    score_breakdown: List[ToolRiskContribution] = field(default_factory=list)


@dataclass(frozen=True)
class _CapabilityRule:
    name: str
    weight: float
    phrases: Tuple[Tuple[str, ...], ...]
    traits: FrozenSet[str]


_CAPABILITY_RULES = (
    _CapabilityRule(
        "database_destruction",
        6.5,
        (("drop", "table"), ("truncate", "table"), ("delete", "database")),
        frozenset({"critical", "destructive", "state_change", "privileged"}),
    ),
    _CapabilityRule(
        "command_execution",
        6.0,
        (
            ("execute", "code"),
            ("run", "command"),
            ("os", "system"),
            ("shell",),
            ("subprocess",),
            ("powershell",),
            ("bash",),
            ("exec",),
            ("eval",),
        ),
        frozenset({"critical", "execution", "state_change", "privileged"}),
    ),
    _CapabilityRule(
        "financial_transaction",
        6.0,
        (
            ("transfer", "funds"),
            ("create", "payment"),
            ("initiate", "transfer"),
            ("charge", "account"),
        ),
        frozenset({"critical", "financial", "state_change"}),
    ),
    _CapabilityRule(
        "privilege_administration",
        6.0,
        (
            ("modify", "permissions"),
            ("grant", "access"),
            ("create", "user"),
            ("elevate", "privilege"),
            ("impersonate", "user"),
        ),
        frozenset({"critical", "privileged", "state_change"}),
    ),
    _CapabilityRule(
        "destructive_mutation",
        4.25,
        (
            ("delete", "file"),
            ("remove", "file"),
            ("destroy", "record"),
            ("delete",),
            ("remove",),
            ("destroy",),
            ("wipe",),
        ),
        frozenset({"destructive", "state_change"}),
    ),
    _CapabilityRule(
        "production_mutation",
        4.0,
        (
            ("write", "production", "db"),
            ("bulk", "update"),
            ("deploy",),
            ("release",),
        ),
        frozenset({"production", "state_change", "privileged"}),
    ),
    _CapabilityRule(
        "outbound_communication",
        3.75,
        (
            ("send", "email"),
            ("send", "message"),
            ("send", "sms"),
            ("post", "slack"),
            ("publish",),
        ),
        frozenset({"egress", "state_change"}),
    ),
    _CapabilityRule(
        "external_network",
        3.5,
        (
            ("external", "api", "call"),
            ("webhook", "post"),
            ("http", "request"),
            ("fetch", "url"),
            ("browser",),
        ),
        frozenset({"egress", "external"}),
    ),
    _CapabilityRule(
        "sensitive_data_access",
        2.75,
        (
            ("read", "credentials"),
            ("access", "secret"),
            ("read", "secret"),
            ("get", "secret"),
        ),
        frozenset({"sensitive_read"}),
    ),
    _CapabilityRule(
        "state_mutation",
        2.25,
        (
            ("write", "file"),
            ("create", "file"),
            ("update", "record"),
            ("insert", "record"),
            ("write",),
            ("create",),
            ("update",),
            ("insert",),
        ),
        frozenset({"state_change"}),
    ),
    _CapabilityRule(
        "database_query",
        2.0,
        (("query", "database"), ("query", "db"), ("query",)),
        frozenset({"read", "potentially_sensitive"}),
    ),
    _CapabilityRule(
        "read_only",
        0.25,
        (
            ("read", "file"),
            ("list", "files"),
            ("get", "record"),
            ("list", "records"),
            ("check", "status"),
            ("get", "info"),
            ("search", "index"),
            ("read",),
            ("list",),
            ("get",),
            ("check",),
            ("describe",),
            ("search",),
        ),
        frozenset({"read_only"}),
    ),
)

_PRIVILEGED_PERMISSION_TOKENS = frozenset(
    {
        "admin",
        "sudo",
        "root",
        "execute",
        "exec",
        "drop",
        "truncate",
        "grant",
        "impersonate",
        "transfer",
    }
)
_MUTATING_PERMISSION_TOKENS = frozenset(
    {"write", "delete", "create", "modify", "update", "send", "publish", "deploy"}
)
_SENSITIVE_PERMISSION_TOKENS = frozenset(
    {"secret", "secrets", "credential", "credentials", "token", "pii"}
)
_EGRESS_PERMISSION_TOKENS = frozenset(
    {"email", "external", "http", "https", "network", "publish", "send", "webhook"}
)
_BROAD_SCOPE_TOKENS = frozenset({"all", "any", "global", "root"})
_UNTRUSTED_SOURCE_TOKENS = frozenset(
    {"external", "untrusted", "user", "model", "llm", "retrieval", "web", "email"}
)
_SENSITIVE_DATA_TOKENS = frozenset(
    {"confidential", "restricted", "secret", "secrets", "credential", "credentials", "pii"}
)
_PRODUCTION_TOKENS = frozenset({"prod", "production", "live", "customer"})
_DOWNSTREAM_OUTPUT_TOKENS = frozenset({"agent", "workflow", "prompt", "model", "llm"})
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_TOKEN = re.compile(r"[a-z0-9]+|\*")


def assess_tool_invocation_risk(
    tool_name: str,
    declared_permissions: Optional[List[str]] = None,
    input_context: Optional[Dict[str, Any]] = None,
    requires_human_approval: bool = False,
    is_idempotent: bool = True,
    has_input_validation: bool = False,
    has_output_sanitization: bool = False,
) -> ToolInvocationRiskResult:
    """Score one proposed tool invocation without making an authorization decision.

    ``input_context`` may declare ``capability`` or ``action``, ``input_source``,
    ``data_classification``, ``contains_secrets``, ``target_environment``,
    ``destination_trusted``, ``output_consumed_by_agent``, ``output_destination``,
    and ``approval_verified``. Unknown keys are ignored.
    """
    context_valid = input_context is None or isinstance(input_context, dict)
    context = input_context if isinstance(input_context, dict) else {}
    permissions, permissions_valid, permissions_truncated = _normalize_permissions(
        declared_permissions
    )
    approval_required, approval_declaration_valid = _strict_safeguard_bool(
        requires_human_approval, default=False
    )
    idempotent, idempotency_declaration_valid = _strict_safeguard_bool(
        is_idempotent, default=True
    )
    input_validated, input_validation_declaration_valid = _strict_safeguard_bool(
        has_input_validation, default=False
    )
    output_sanitized, output_sanitization_declaration_valid = _strict_safeguard_bool(
        has_output_sanitization, default=False
    )
    capability = _classify_capability(tool_name, context)
    contributions: List[ToolRiskContribution] = []
    recommendations: List[str] = []

    def add(indicator: str, weight: float, detail: str, recommendation: str = "") -> None:
        if any(item.indicator == indicator for item in contributions):
            return
        contributions.append(ToolRiskContribution(indicator, weight, detail))
        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    malformed_safeguards = [
        name
        for name, valid in (
            ("requires_human_approval", approval_declaration_valid),
            ("is_idempotent", idempotency_declaration_valid),
            ("has_input_validation", input_validation_declaration_valid),
            ("has_output_sanitization", output_sanitization_declaration_valid),
        )
        if not valid
    ]
    if malformed_safeguards:
        add(
            "malformed_safeguard_evidence",
            1.25,
            f"Safeguard declarations are not strict booleans: {malformed_safeguards}",
            "Emit typed boolean safeguard evidence from the invocation policy evaluator",
        )
    if not context_valid:
        add(
            "malformed_invocation_context",
            1.0,
            "Invocation context is not an object and could not be evaluated",
            "Provide a bounded structured invocation context",
        )
    if not permissions_valid or permissions_truncated:
        add(
            "malformed_permission_scope",
            1.5,
            "Permission scope is malformed or exceeds the analysis bound",
            "Provide a bounded list of explicit permission strings",
        )

    if capability["matched_rules"]:
        add(
            "intrinsic_capability",
            capability["weight"],
            f"Intrinsic capability class: {capability['primary_rule']}",
        )
    else:
        add(
            "unclassified_capability",
            1.5,
            f"Tool capability is unclassified: {tool_name or '<empty>'}",
            "Classify the tool and its operation in the agent tool registry",
        )

    permission_analysis = _analyze_permissions(permissions)
    if permission_analysis["broad"]:
        add(
            "broad_permission_scope",
            1.5,
            f"Broad or wildcard permission scope: {permission_analysis['broad']}",
            "Replace wildcard permissions with resource- and action-scoped grants",
        )
    if permission_analysis["privileged"]:
        add(
            "privileged_permissions",
            min(0.75 * len(permission_analysis["privileged"]), 2.25),
            f"Privileged permissions: {permission_analysis['privileged']}",
            "Apply least privilege and short-lived credentials to this tool",
        )
    if permission_analysis["mutating"]:
        add(
            "mutating_permissions",
            min(0.4 * len(permission_analysis["mutating"]), 1.2),
            f"State-mutating permissions: {permission_analysis['mutating']}",
        )
    if permission_analysis["sensitive"]:
        add(
            "sensitive_data_permissions",
            0.5,
            f"Sensitive-data permissions: {permission_analysis['sensitive']}",
            "Scope sensitive-data access to the minimum fields and records required",
        )

    traits = capability["traits"]
    dangerous = bool(
        traits
        & {
            "critical",
            "execution",
            "destructive",
            "financial",
            "privileged",
            "state_change",
            "egress",
        }
    ) or bool(
        permission_analysis["privileged"]
        or permission_analysis["mutating"]
        or permission_analysis["egress"]
    )
    untrusted_input = _context_has_tokens(context.get("input_source"), _UNTRUSTED_SOURCE_TOKENS)
    sensitive_data = _context_has_tokens(
        context.get("data_classification"), _SENSITIVE_DATA_TOKENS
    ) or _context_bool(context, "contains_secrets")
    production_target = _context_has_tokens(
        context.get("target_environment"), _PRODUCTION_TOKENS
    ) or "production" in traits
    downstream_output = _context_bool(
        context, "output_consumed_by_agent"
    ) or _context_has_tokens(context.get("output_destination"), _DOWNSTREAM_OUTPUT_TOKENS)

    if not input_validated:
        add(
            "missing_input_validation",
            0.75,
            "No input-validation evidence is declared",
            "Validate inputs against a strict schema and reject unexpected fields",
        )
    if untrusted_input and dangerous and not input_validated:
        add(
            "untrusted_input_to_dangerous_capability",
            1.75,
            "Unvalidated external, user, retrieval, or model input reaches a dangerous capability",
            "Use allowlisted structured arguments and isolate instructions from tool data",
        )
    if "execution" in traits and permission_analysis["broad"]:
        add(
            "execution_with_broad_permissions",
            1.25,
            "Code or command execution is combined with broad permission scope",
            "Run the tool in a sandbox with an explicit filesystem and network allowlist",
        )
    if "read_only" in traits and (
        permission_analysis["privileged"] or permission_analysis["mutating"]
    ):
        add(
            "permissions_exceed_capability",
            1.25,
            "A read-only capability has mutating or privileged permissions",
            "Remove permissions that are not required by the declared operation",
        )
    if dangerous and not permissions:
        add(
            "undeclared_permission_scope",
            0.75,
            "Dangerous capability has no declared permission scope",
            "Declare an explicit deny-by-default permission envelope",
        )

    egress = "egress" in traits or bool(permission_analysis["egress"])
    sensitive_access = sensitive_data or "sensitive_read" in traits
    destination_is_trusted = _context_bool(context, "destination_trusted")
    if egress and sensitive_access and not destination_is_trusted:
        add(
            "sensitive_data_egress_path",
            2.25,
            "Sensitive data can reach an external destination without verified destination trust",
            "Block sensitive fields from egress and allowlist authenticated destinations",
        )
    if production_target and (
        traits & {"state_change", "destructive", "privileged"}
        or permission_analysis["mutating"]
        or permission_analysis["privileged"]
    ):
        add(
            "production_state_change",
            1.25,
            "The invocation can change production or live resources",
            "Require a production change gate, rollback plan, and bounded resource scope",
        )

    if not idempotent:
        weight = (
            1.25
            if "state_change" in traits or permission_analysis["mutating"]
            else 0.75
        )
        add(
            "non_idempotent_invocation",
            weight,
            "Repeated invocation can produce cumulative or divergent side effects",
            "Require an idempotency key and durable duplicate-suppression window",
        )
    if not output_sanitized:
        if downstream_output and (
            traits & {"egress", "external", "sensitive_read"}
            or permission_analysis["egress"]
        ):
            add(
                "unsanitized_output_to_agent",
                1.25,
                "Untrusted tool output can become downstream agent or prompt input",
                "Treat tool output as data, validate its schema, and strip executable instructions",
            )
        else:
            add(
                "missing_output_sanitization",
                0.25,
                "No output-sanitization evidence is declared",
                "Validate tool output before it reaches downstream reasoning or actions",
            )

    if dangerous and not approval_required:
        add(
            "missing_human_approval_gate",
            1.5,
            "Dangerous capability lacks a human approval requirement",
            "Require explicit, invocation-bound human approval",
        )
    if (
        dangerous
        and approval_required
        and "approval_verified" not in context
    ):
        add(
            "approval_evidence_missing",
            1.5,
            "A required approval gate has no invocation-bound verification evidence",
            "Bind a trusted approval decision to the exact tool, arguments, actor, and expiry",
        )
    if (
        dangerous
        and approval_required
        and "approval_verified" in context
        and context.get("approval_verified") is not True
    ):
        add(
            "approval_not_verified",
            2.0,
            "A required approval gate is present but approval evidence is not verified",
            "Deny execution until a trusted approval record is bound to this invocation",
        )

    score = min(round(sum(item.weight for item in contributions), 2), 10.0)
    tier = _risk_tier(score)
    if tier == ToolRiskTier.CRITICAL:
        recommendation = "Sandbox or disable this tool until critical risk paths are controlled"
        if recommendation not in recommendations:
            recommendations.append(recommendation)

    return ToolInvocationRiskResult(
        tool_name=tool_name,
        risk_tier=tier,
        score=score,
        risk_factors=[item.detail for item in contributions],
        recommendations=recommendations,
        mitre_atlas_refs=[
            "AML.T0053 AI Agent Tool Invocation",
            "AML.T0051 LLM Prompt Injection",
        ],
        owasp_refs=["LLM06 Excessive Agency"],
        capability_class=capability["primary_rule"],
        matched_capabilities=capability["matched_rules"],
        score_breakdown=contributions,
    )


def _classify_capability(tool_name: str, context: Dict[str, Any]) -> Dict[str, Any]:
    tool_tokens = _tokenize(tool_name)
    context_values = [context.get("capability"), context.get("action"), context.get("operation")]
    context_tokens = [_tokenize(value) for value in context_values if value not in (None, "")]
    tool_matches = [
        rule
        for rule in _CAPABILITY_RULES
        if any(_contains_phrase(tool_tokens, phrase) for phrase in rule.phrases)
    ]
    context_matches = [
        rule
        for rule in _CAPABILITY_RULES
        if any(
            _contains_phrase(tokens, phrase)
            for tokens in context_tokens
            for phrase in rule.phrases
        )
    ]
    if not tool_matches:
        context_matches = [rule for rule in context_matches if rule.weight >= 1.5]
    matches = list({rule.name: rule for rule in tool_matches + context_matches}.values())
    if not matches:
        return {
            "primary_rule": "unclassified",
            "matched_rules": [],
            "traits": frozenset(),
            "weight": 1.5,
        }
    matches.sort(key=lambda rule: (-rule.weight, rule.name))
    traits = frozenset(trait for rule in matches for trait in rule.traits)
    return {
        "primary_rule": matches[0].name,
        "matched_rules": [rule.name for rule in matches],
        "traits": traits,
        "weight": matches[0].weight,
    }


def _normalize_permissions(value: Optional[Sequence[str]]):
    if value in (None, ""):
        return [], True, False
    if isinstance(value, str):
        value = [value]
    elif not isinstance(value, (list, tuple, set, frozenset)):
        return [], False, False
    items = list(value)
    truncated = len(items) > _MAX_PERMISSIONS
    valid = True
    normalized = set()
    for permission in items[:_MAX_PERMISSIONS]:
        if not isinstance(permission, str):
            valid = False
            continue
        candidate = permission.strip().lower()
        if not candidate or len(candidate) > _MAX_PERMISSION_CHARS:
            valid = False
            continue
        normalized.add(candidate)
    return sorted(normalized), valid, truncated


def _strict_safeguard_bool(value, *, default):
    if isinstance(value, bool):
        return value, True
    if value is None:
        return default, True
    return False, False


def _analyze_permissions(permissions: List[str]) -> Dict[str, List[str]]:
    broad = []
    privileged = []
    mutating = []
    sensitive = []
    egress = []
    for permission in permissions:
        tokens = set(_tokenize(permission))
        if "*" in tokens or tokens & _BROAD_SCOPE_TOKENS:
            broad.append(permission)
        if tokens & _PRIVILEGED_PERMISSION_TOKENS:
            privileged.append(permission)
        if tokens & _MUTATING_PERMISSION_TOKENS:
            mutating.append(permission)
        if tokens & _SENSITIVE_PERMISSION_TOKENS:
            sensitive.append(permission)
        if tokens & _EGRESS_PERMISSION_TOKENS:
            egress.append(permission)
    return {
        "broad": broad,
        "privileged": privileged,
        "mutating": mutating,
        "sensitive": sensitive,
        "egress": egress,
    }


def _tokenize(value: Any) -> Tuple[str, ...]:
    expanded = _CAMEL_BOUNDARY.sub(" ", str(value or ""))
    return tuple(_TOKEN.findall(expanded.lower()))


def _contains_phrase(tokens: Tuple[str, ...], phrase: Tuple[str, ...]) -> bool:
    width = len(phrase)
    return any(tokens[index : index + width] == phrase for index in range(len(tokens) - width + 1))


def _context_has_tokens(value: Any, expected: FrozenSet[str]) -> bool:
    return bool(set(_tokenize(value)) & expected)


def _context_bool(context: Dict[str, Any], key: str) -> bool:
    value = context.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "enabled"}


def _risk_tier(score: float) -> ToolRiskTier:
    if score >= 8.0:
        return ToolRiskTier.CRITICAL
    if score >= 5.5:
        return ToolRiskTier.HIGH
    if score >= 3.0:
        return ToolRiskTier.MEDIUM
    if score >= 1.5:
        return ToolRiskTier.LOW
    return ToolRiskTier.SAFE
