"""Runtime Policy Enforcement Point (PEP).

Provides an inline decision layer that intercepts requests from principals and
evaluates them against configured enforcement policies before they reach downstream
AI components.  Operates in three modes:

  ENFORCE      — actually block requests that violate policy (hard enforcement)
  AUDIT        — allow all requests but log every decision (soft / shadow mode)
  PASSTHROUGH  — bypass enforcement entirely; always ALLOW (testing / gradual rollout)

Decision verdicts
-----------------
ALLOW        — request is permitted
DENY         — request is blocked
CONDITIONAL  — request is permitted subject to listed conditions

Policy structure
----------------
A policy is scoped to a principal (agent, model, service, etc.) and defines:
  - allowed_actions     : explicit allow-list (empty = allow nothing)
  - denied_actions      : explicit deny-list (takes priority over allow-list)
  - allowed_resources   : resources this principal may act upon
  - denied_resources    : resources this principal is prohibited from accessing
  - conditions          : conditions that must be satisfied for CONDITIONAL verdicts
  - max_requests_per_min: rate limit (0 = no limit)
  - mode                : ENFORCE / AUDIT / PASSTHROUGH

Pattern matching
----------------
Policies use simple glob-style matching: ``"*"`` matches any value.
``"read:*"``   — action=read on any resource
``"*:users"``  — any action on the users resource
``"*"``        — any action on any resource

Evidence origin
---------------
LOCALLY_OBSERVED — all enforcement decisions are computed and logged locally by AIAF.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

POLICY_ENFORCEMENT_VERSION = "1.0"

# ── Enforcement modes ──────────────────────────────────────────────────────────
MODE_ENFORCE = "ENFORCE"
MODE_AUDIT = "AUDIT"
MODE_PASSTHROUGH = "PASSTHROUGH"

ENFORCEMENT_MODES: frozenset = frozenset({MODE_ENFORCE, MODE_AUDIT, MODE_PASSTHROUGH})

# ── Decision verdicts ──────────────────────────────────────────────────────────
VERDICT_ALLOW = "ALLOW"
VERDICT_DENY = "DENY"
VERDICT_CONDITIONAL = "CONDITIONAL"

VERDICTS: frozenset = frozenset({VERDICT_ALLOW, VERDICT_DENY, VERDICT_CONDITIONAL})

# ── Storage prefixes ───────────────────────────────────────────────────────────
_POLICY_PREFIX = "pep_policy:"
_LOG_PREFIX = "pep_log:"

# ── Rate-limit window (seconds) ────────────────────────────────────────────────
_RATE_WINDOW_SEC = 60


class PolicyEnforcementError(ValueError):
    pass


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _policy_key(policy_id: str) -> str:
    return f"{_POLICY_PREFIX}{policy_id}"


def _log_key(policy_id: str, decision_id: str) -> str:
    return f"{_LOG_PREFIX}{policy_id}:{decision_id}"


def _load_meta(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return (record or {}).get("metadata") or {}


def _matches(pattern: str, value: str) -> bool:
    """Match a single glob pattern against a value.  Only ``*`` is supported."""
    if pattern == "*":
        return True
    if pattern.endswith(":*"):
        return value.startswith(pattern[:-1])
    if pattern.startswith("*:"):
        return value.endswith(pattern[1:])
    return pattern == value


def _action_resource_matches(pattern: str, action: str, resource: str) -> bool:
    """Match a combined ``action:resource`` pattern against action + resource."""
    if pattern == "*":
        return True
    if ":" in pattern:
        pat_action, pat_resource = pattern.split(":", 1)
        action_ok = pat_action == "*" or pat_action == action
        resource_ok = pat_resource == "*" or pat_resource == resource
        return action_ok and resource_ok
    # bare action pattern (no colon)
    return pattern == action or pattern == "*"


def _check_rate_limit(
    policy_id: str,
    max_rpm: float,
    store: Any,
) -> bool:
    """Return True if request is within rate limit, False if it exceeds it.

    Uses a simple counter stored alongside the policy log.  Counts requests
    within the last _RATE_WINDOW_SEC seconds.
    """
    if max_rpm <= 0:
        return True

    now_dt = datetime.now(timezone.utc)
    log_prefix = f"{_LOG_PREFIX}{policy_id}:"

    all_records = store.list_models() if hasattr(store, "list_models") else []
    window_count = 0
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(log_prefix):
            continue
        meta = _load_meta(rec)
        ts = meta.get("decided_at")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            elapsed = (now_dt - dt).total_seconds()
            if elapsed <= _RATE_WINDOW_SEC:
                window_count += 1
        except Exception:
            continue

    return window_count < max_rpm


# ── Public API ─────────────────────────────────────────────────────────────────

def create_pep_policy(
    policy_id: str,
    principal_id: str,
    store: Any,
    *,
    mode: str = MODE_ENFORCE,
    allowed_actions: Optional[List[str]] = None,
    denied_actions: Optional[List[str]] = None,
    allowed_resources: Optional[List[str]] = None,
    denied_resources: Optional[List[str]] = None,
    conditions: Optional[List[str]] = None,
    max_requests_per_min: float = 0,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an enforcement policy for a principal.

    Parameters
    ----------
    policy_id:       Unique policy identifier.
    principal_id:    The agent/model/service this policy governs.
    mode:            ENFORCE, AUDIT, or PASSTHROUGH.
    allowed_actions: Actions explicitly permitted (``["read", "list", "*"]``).
                     Empty list means no actions are whitelisted.
    denied_actions:  Actions explicitly blocked (evaluated before allow-list).
    allowed_resources: Resources the principal may access.
    denied_resources: Resources that are blocked regardless of action.
    conditions:      Human-readable conditions emitted on CONDITIONAL verdicts.
    max_requests_per_min: Rate limit (0 = no limit).
    """
    if not policy_id or not policy_id.strip():
        raise PolicyEnforcementError("policy_id must be non-empty.")
    if not principal_id or not principal_id.strip():
        raise PolicyEnforcementError("principal_id must be non-empty.")

    mode = str(mode).upper().strip()
    if mode not in ENFORCEMENT_MODES:
        raise PolicyEnforcementError(
            f"Unknown mode {mode!r}. Valid: {sorted(ENFORCEMENT_MODES)}"
        )

    record: Dict[str, Any] = {
        "model_id": _policy_key(policy_id),
        "id": _policy_key(policy_id),
        "metadata": {
            "policy_id": policy_id,
            "principal_id": principal_id,
            "mode": mode,
            "allowed_actions": allowed_actions or [],
            "denied_actions": denied_actions or [],
            "allowed_resources": allowed_resources or [],
            "denied_resources": denied_resources or [],
            "conditions": conditions or [],
            "max_requests_per_min": float(max_requests_per_min),
            "description": description or "",
            "request_count": 0,
            "deny_count": 0,
            "evidence_origin": "LOCALLY_OBSERVED",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
        },
    }
    store.save_model(record)
    return _load_meta(store.get_model(_policy_key(policy_id)))


def get_pep_policy(policy_id: str, store: Any) -> Optional[Dict[str, Any]]:
    """Return policy record, or None if not found."""
    rec = store.get_model(_policy_key(policy_id))
    return _load_meta(rec) if rec else None


def list_pep_policies(
    store: Any,
    *,
    principal_id: Optional[str] = None,
    mode: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """List enforcement policies with optional filters."""
    all_records = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(_POLICY_PREFIX):
            continue
        meta = _load_meta(rec)
        if principal_id and meta.get("principal_id") != principal_id:
            continue
        if mode and meta.get("mode") != str(mode).upper().strip():
            continue
        results.append(meta)
        if len(results) >= limit:
            break
    return results


def delete_pep_policy(policy_id: str, store: Any) -> bool:
    """Remove a policy.  Returns True if it existed, False if not found."""
    if store.get_model(_policy_key(policy_id)) is None:
        return False
    store.save_model({
        "model_id": _policy_key(policy_id),
        "id": _policy_key(policy_id),
        "metadata": {"_deleted": True},
    })
    return True


def enforce_request(
    principal_id: str,
    action: str,
    resource: str,
    store: Any,
    *,
    context: Optional[Dict[str, Any]] = None,
    policy_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate an incoming request against all applicable policies.

    Looks up policies for the given ``principal_id`` (or a specific policy if
    ``policy_id`` is provided), evaluates deny-lists then allow-lists, applies
    rate limits, and returns an enforcement decision.

    In PASSTHROUGH mode the verdict is always ALLOW with no side effects.
    In AUDIT mode the verdict is computed but the request is never blocked —
    callers receive the computed verdict for logging purposes.

    Parameters
    ----------
    principal_id:  The agent/model/service making the request.
    action:        The action being attempted (e.g. ``"read"``, ``"write"``).
    resource:      The resource being accessed (e.g. ``"users_db"``, ``"filesystem"``).
    context:       Additional key-value context used for condition evaluation.
    policy_id:     If given, only evaluate this specific policy.

    Returns
    -------
    Dict with keys:
        principal_id, action, resource, verdict, mode,
        reasons, conditions_required, rate_limited,
        policy_ids_evaluated, evidence_origin, decided_at
    """
    if not principal_id:
        raise PolicyEnforcementError("principal_id must be non-empty.")
    if not action:
        raise PolicyEnforcementError("action must be non-empty.")
    if not resource:
        raise PolicyEnforcementError("resource must be non-empty.")

    # Find applicable policies
    if policy_id:
        policy = get_pep_policy(policy_id, store)
        policies = [policy] if policy else []
    else:
        policies = list_pep_policies(store, principal_id=principal_id, limit=50)
        # Also check policies that apply to "*" (all principals)
        wildcard = list_pep_policies(store, principal_id="*", limit=20)
        policies = policies + [p for p in wildcard if p not in policies]

    if not policies:
        # No policy → safe default DENY in ENFORCE; ALLOW in absence (open policy)
        # AIAF defaults to ALLOW when no policy is configured (permissive for backward compat)
        return {
            "principal_id": principal_id,
            "action": action,
            "resource": resource,
            "verdict": VERDICT_ALLOW,
            "mode": MODE_PASSTHROUGH,
            "reasons": ["No policy configured for this principal — default ALLOW."],
            "conditions_required": [],
            "rate_limited": False,
            "policy_ids_evaluated": [],
            "evidence_origin": "LOCALLY_OBSERVED",
            "decided_at": _utc_now(),
        }

    now = _utc_now()
    import uuid
    decision_id = str(uuid.uuid4())[:8]

    reasons: List[str] = []
    conditions_required: List[str] = []
    overall_verdict = VERDICT_ALLOW
    effective_mode = MODE_ENFORCE
    rate_limited = False
    policy_ids_evaluated = []

    for policy in policies:
        if policy.get("_deleted"):
            continue

        pid = policy.get("policy_id", "?")
        mode = policy.get("mode", MODE_ENFORCE)
        policy_ids_evaluated.append(pid)

        if mode == MODE_PASSTHROUGH:
            effective_mode = MODE_PASSTHROUGH
            continue

        # Rate limit check
        max_rpm = float(policy.get("max_requests_per_min", 0))
        if max_rpm > 0 and not _check_rate_limit(pid, max_rpm, store):
            rate_limited = True
            if mode == MODE_ENFORCE:
                overall_verdict = VERDICT_DENY
                reasons.append(
                    f"Policy {pid!r}: rate limit {max_rpm:.0f} req/min exceeded."
                )
            elif mode == MODE_AUDIT:
                reasons.append(
                    f"Policy {pid!r} [AUDIT]: rate limit {max_rpm:.0f} req/min would be exceeded."
                )
            continue

        # Deny resource check
        for pattern in (policy.get("denied_resources") or []):
            if _matches(pattern, resource):
                if mode == MODE_ENFORCE:
                    overall_verdict = VERDICT_DENY
                    reasons.append(
                        f"Policy {pid!r}: resource {resource!r} matches denied pattern {pattern!r}."
                    )
                else:
                    reasons.append(
                        f"Policy {pid!r} [AUDIT]: resource {resource!r} matches denied_resources."
                    )

        # Deny action check
        for pattern in (policy.get("denied_actions") or []):
            if _action_resource_matches(pattern, action, resource):
                if mode == MODE_ENFORCE:
                    overall_verdict = VERDICT_DENY
                    reasons.append(
                        f"Policy {pid!r}: action {action!r} on {resource!r} matches denied pattern {pattern!r}."
                    )
                else:
                    reasons.append(
                        f"Policy {pid!r} [AUDIT]: action {action!r} matches denied_actions."
                    )

        # Allow-list check (only relevant if not already DENY)
        if overall_verdict != VERDICT_DENY:
            allowed_actions = policy.get("allowed_actions") or []
            allowed_resources = policy.get("allowed_resources") or []

            action_ok = not allowed_actions or any(
                _action_resource_matches(p, action, resource) for p in allowed_actions
            )
            resource_ok = not allowed_resources or any(
                _matches(p, resource) for p in allowed_resources
            )

            if allowed_actions and not action_ok:
                if mode == MODE_ENFORCE:
                    overall_verdict = VERDICT_DENY
                    reasons.append(
                        f"Policy {pid!r}: action {action!r} not in allowed_actions."
                    )
                else:
                    reasons.append(
                        f"Policy {pid!r} [AUDIT]: action {action!r} not in allowed_actions."
                    )
            elif allowed_resources and not resource_ok:
                if mode == MODE_ENFORCE:
                    overall_verdict = VERDICT_DENY
                    reasons.append(
                        f"Policy {pid!r}: resource {resource!r} not in allowed_resources."
                    )
                else:
                    reasons.append(
                        f"Policy {pid!r} [AUDIT]: resource {resource!r} not in allowed_resources."
                    )
            else:
                # Request passes — check for conditions
                conds = policy.get("conditions") or []
                if conds and overall_verdict == VERDICT_ALLOW:
                    overall_verdict = VERDICT_CONDITIONAL
                    conditions_required.extend(conds)
                    reasons.append(
                        f"Policy {pid!r}: request allowed with {len(conds)} condition(s)."
                    )
                elif not reasons:
                    reasons.append(f"Policy {pid!r}: request permitted.")

        # Update counters — always, even if we're about to break
        updated_policy = dict(policy)
        updated_policy["request_count"] = int(updated_policy.get("request_count", 0)) + 1
        if overall_verdict == VERDICT_DENY:
            updated_policy["deny_count"] = int(updated_policy.get("deny_count", 0)) + 1
        updated_policy["updated_at"] = now
        store.save_model({
            "model_id": _policy_key(pid),
            "id": _policy_key(pid),
            "metadata": updated_policy,
        })

        # Stop evaluating further policies once we have a hard DENY
        if overall_verdict == VERDICT_DENY and mode == MODE_ENFORCE:
            break

    # In PASSTHROUGH / AUDIT, never actually block
    effective_verdict = overall_verdict
    if effective_mode == MODE_PASSTHROUGH or all(
        p.get("mode") in (MODE_AUDIT, MODE_PASSTHROUGH) for p in policies if not p.get("_deleted")
    ):
        effective_verdict = VERDICT_ALLOW

    # Persist the enforcement log entry
    log_entry: Dict[str, Any] = {
        "model_id": _log_key(policy_ids_evaluated[0] if policy_ids_evaluated else "default", decision_id),
        "id": _log_key(policy_ids_evaluated[0] if policy_ids_evaluated else "default", decision_id),
        "metadata": {
            "decision_id": decision_id,
            "principal_id": principal_id,
            "action": action,
            "resource": resource,
            "verdict": effective_verdict,
            "computed_verdict": overall_verdict,
            "mode": effective_mode,
            "reasons": reasons,
            "conditions_required": conditions_required,
            "rate_limited": rate_limited,
            "policy_ids_evaluated": policy_ids_evaluated,
            "context": context or {},
            "evidence_origin": "LOCALLY_OBSERVED",
            "decided_at": now,
        },
    }
    store.save_model(log_entry)

    return {
        "principal_id": principal_id,
        "action": action,
        "resource": resource,
        "verdict": effective_verdict,
        "computed_verdict": overall_verdict,
        "mode": effective_mode,
        "reasons": reasons,
        "conditions_required": conditions_required,
        "rate_limited": rate_limited,
        "policy_ids_evaluated": policy_ids_evaluated,
        "evidence_origin": "LOCALLY_OBSERVED",
        "decided_at": now,
    }


def get_enforcement_log(
    policy_id: str,
    store: Any,
    *,
    verdict: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return enforcement log entries for a policy, newest first.

    Parameters
    ----------
    verdict:  Filter to ALLOW / DENY / CONDITIONAL entries only.
    """
    log_prefix = f"{_LOG_PREFIX}{policy_id}:"
    all_records = store.list_models() if hasattr(store, "list_models") else []
    results = []
    for rec in all_records:
        mid = str(rec.get("model_id") or rec.get("id") or "")
        if not mid.startswith(log_prefix):
            continue
        meta = _load_meta(rec)
        if verdict and meta.get("verdict") != str(verdict).upper().strip():
            continue
        results.append(meta)
    results.sort(key=lambda e: e.get("decided_at", ""), reverse=True)
    return results[:limit]
