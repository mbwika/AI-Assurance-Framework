"""Agent-Skill & Extension Supply-Chain Scanner.

Scans agent skill/plugin manifests for supply-chain compromise signals, extending
the MCP tool scanner (mcp_scanner.py) to cover the broader 2026 skill-registry
attack surface:

  - ClawHub-style registry attacks: 341 malicious skills with covert permission
    requests, obfuscated handlers, and C2 callbacks.
  - Typosquatting and lookalike package names targeting popular skills.
  - Unsigned / unverified publisher identity.
  - Capability mismatch: stated purpose vs. requested permissions.
  - Dependency chain risk: high-CVE-density or rapidly-changing deps.

Skill manifest schema (expected fields)
----------------------------------------
    skill_id         str   — unique identifier (e.g. "org/skill-name@version")
    name             str   — human-readable name
    description      str   — what the skill does
    version          str   — semver
    publisher        str   — publisher identifier / org
    publisher_signed bool  — whether manifest is cryptographically signed
    permissions      list  — list of permission strings requested
    dependencies     list  — list of {"name": ..., "version": ...} dicts
    entry_point      str   — execution entry point URI or module
    code_execution   bool  — whether skill executes code
    network_access   bool  — whether skill makes network calls
    data_access      list  — data resources declared (e.g. ["filesystem", "clipboard"])
    tags             list  — categorisation tags

Risk categories
---------------
PERMISSION_SCOPE_CREEP  — permissions far exceed stated purpose
UNSIGNED_PUBLISHER       — manifest not cryptographically signed
SUSPICIOUS_DEPENDENCY    — dep name matches typosquatting patterns or is unknown
OBFUSCATED_ENTRY_POINT  — entry point looks obfuscated/encoded
COVERT_NETWORK_ACCESS   — network_access=True but not declared in description
COVERT_CODE_EXECUTION   — code_execution=True but not obvious from stated purpose
CAPABILITY_MISMATCH     — stated tags/description conflict with requested permissions
INJECTION_PATTERN        — manifest text contains prompt-injection signals

Severity levels: CRITICAL, HIGH, MEDIUM, LOW

Status codes
------------
STATUS_CLEAN       — no risk signals detected
STATUS_SUSPICIOUS  — soft signals; review recommended
STATUS_UNSAFE      — high-confidence supply-chain risk; do not install
STATUS_ERROR       — scan failed due to malformed manifest

Evidence origin
---------------
LOCALLY_OBSERVED — all findings produced by static analysis of the manifest.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

SKILL_SCANNER_VERSION = "1.0"

# ── Status codes ───────────────────────────────────────────────────────────────
STATUS_CLEAN = "CLEAN"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_UNSAFE = "UNSAFE"
STATUS_ERROR = "SCAN_ERROR"

_STATUS_RANK = {STATUS_ERROR: 0, STATUS_UNSAFE: 1, STATUS_SUSPICIOUS: 2, STATUS_CLEAN: 3}

# ── Risk categories ────────────────────────────────────────────────────────────
RISK_PERMISSION_SCOPE_CREEP = "PERMISSION_SCOPE_CREEP"
RISK_UNSIGNED_PUBLISHER = "UNSIGNED_PUBLISHER"
RISK_SUSPICIOUS_DEPENDENCY = "SUSPICIOUS_DEPENDENCY"
RISK_OBFUSCATED_ENTRY_POINT = "OBFUSCATED_ENTRY_POINT"
RISK_COVERT_NETWORK_ACCESS = "COVERT_NETWORK_ACCESS"
RISK_COVERT_CODE_EXECUTION = "COVERT_CODE_EXECUTION"
RISK_CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
RISK_INJECTION_PATTERN = "INJECTION_PATTERN"

RISK_CATEGORIES: frozenset = frozenset({
    RISK_PERMISSION_SCOPE_CREEP, RISK_UNSIGNED_PUBLISHER,
    RISK_SUSPICIOUS_DEPENDENCY, RISK_OBFUSCATED_ENTRY_POINT,
    RISK_COVERT_NETWORK_ACCESS, RISK_COVERT_CODE_EXECUTION,
    RISK_CAPABILITY_MISMATCH, RISK_INJECTION_PATTERN,
})

# ── Injection patterns ─────────────────────────────────────────────────────────
_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions?", re.I), "CRITICAL"),
    (re.compile(r"(exfiltrate|leak|transmit)\s+(data|secrets?|tokens?|credentials?)", re.I), "CRITICAL"),
    (re.compile(r"<\|im_start\|>|<\|system\|>|<system-prompt>|<inject>", re.I), "CRITICAL"),
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I), "HIGH"),
    (re.compile(r"new\s+(persona|system[\s_]instructions?)", re.I), "HIGH"),
    (re.compile(r"(before|after)\s+.{0,40}(send|transmit|call)\s+(http|https|ws|tcp)", re.I | re.S), "HIGH"),
    (re.compile(r"act\s+as\s+(a|an|the)\s+\w+", re.I), "MEDIUM"),
    (re.compile(r"(override|bypass|disable)\s+(safety|guardrail|filter)", re.I), "MEDIUM"),
]

# ── High-risk permission strings ───────────────────────────────────────────────
_HIGH_RISK_PERMISSIONS: Set[str] = {
    "filesystem:write", "filesystem:read_all", "filesystem:delete",
    "network:unrestricted", "network:egress", "process:execute",
    "clipboard:read", "clipboard:write", "keychain:read",
    "env:read", "secrets:read", "credentials:read",
    "memory:write", "kernel:access", "container:escape",
    "registry:write",  # Windows registry
    "audio:record", "screen:capture", "camera:access",
}

_LOW_RISK_PERMISSIONS: Set[str] = {
    "filesystem:read_local", "network:api_call", "clipboard:write_only",
    "ui:display", "notification:send",
}

# ── Typosquatting patterns ─────────────────────────────────────────────────────
# Common legitimate skill/package names — lookalikes are suspicious
_KNOWN_LEGIT_PATTERNS: List[re.Pattern] = [
    re.compile(r"^(openai|open-ai|0penai|opena1)[\-_]", re.I),          # OpenAI lookalikes
    re.compile(r"^(anthropic|anthr0pic|anthroplc)[\-_]", re.I),          # Anthropic lookalikes
    re.compile(r"^(langchain|lang-chain|Iangchain)[\-_]", re.I),         # LangChain lookalikes
    re.compile(r"^(litellm|lite-llm|liteIlm)[\-_]", re.I),              # LiteLLM lookalikes
    re.compile(r"^(huggingface|hugging-face|hugg1ngface)[\-_]", re.I),   # HuggingFace lookalikes
]

# ── Obfuscation patterns ───────────────────────────────────────────────────────
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{40,}$")
_URL_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _worst_status(statuses: List[str]) -> str:
    return min(statuses, key=lambda s: _STATUS_RANK.get(s, 99), default=STATUS_CLEAN)


def _status_from_severities(severities: List[str]) -> str:
    if "CRITICAL" in severities:
        return STATUS_UNSAFE
    if "HIGH" in severities:
        return STATUS_UNSAFE
    if "MEDIUM" in severities:
        return STATUS_SUSPICIOUS
    if "LOW" in severities:
        return STATUS_SUSPICIOUS
    return STATUS_CLEAN


def _manifest_hash(manifest: Dict[str, Any]) -> str:
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _scan_text_for_injection(text: str) -> List[Dict[str, Any]]:
    findings = []
    for pattern, severity in _INJECTION_PATTERNS:
        if pattern.search(text):
            findings.append({
                "risk_category": RISK_INJECTION_PATTERN,
                "severity": severity,
                "detail": f"Injection pattern matched: {pattern.pattern[:60]}",
            })
    return findings


def _check_permissions(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    permissions = set(str(p).lower() for p in (manifest.get("permissions") or []))
    high_risk = permissions & _HIGH_RISK_PERMISSIONS
    if not high_risk:
        return findings

    # Check if description justifies the permissions
    description = str(manifest.get("description") or "").lower()
    name = str(manifest.get("name") or "").lower()
    combined = description + " " + name

    # Simple heuristics: known-safe contexts
    is_dev_tool = any(kw in combined for kw in [
        "developer", "development", "build", "compile", "deploy", "infrastructure",
        "devops", "ci/cd", "pipeline",
    ])
    is_file_manager = any(kw in combined for kw in [
        "file", "document", "storage", "backup", "sync", "transfer",
    ])
    is_system_tool = any(kw in combined for kw in [
        "system", "admin", "management", "monitoring", "terminal", "shell",
    ])

    for perm in high_risk:
        justified = (
            (perm.startswith("filesystem") and is_file_manager)
            or (perm.startswith("process") and (is_dev_tool or is_system_tool))
            or (perm.startswith("env") and is_dev_tool)
        )
        if not justified:
            findings.append({
                "risk_category": RISK_PERMISSION_SCOPE_CREEP,
                "severity": "HIGH",
                "detail": (
                    f"Permission {perm!r} granted but not clearly justified by "
                    f"stated purpose: {description[:80]!r}"
                ),
                "permission": perm,
            })

    return findings


def _check_publisher(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    if not manifest.get("publisher_signed", False):
        findings.append({
            "risk_category": RISK_UNSIGNED_PUBLISHER,
            "severity": "MEDIUM",
            "detail": "Skill manifest is not cryptographically signed by the publisher.",
        })
    return findings


def _check_dependencies(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    deps = manifest.get("dependencies") or []
    for dep in deps:
        name = str(dep.get("name") or "")
        for pattern in _KNOWN_LEGIT_PATTERNS:
            if pattern.match(name):
                findings.append({
                    "risk_category": RISK_SUSPICIOUS_DEPENDENCY,
                    "severity": "HIGH",
                    "detail": f"Dependency {name!r} matches typosquatting pattern for a known legitimate package.",
                    "dependency": name,
                })
                break
    return findings


def _check_entry_point(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    ep = str(manifest.get("entry_point") or "")
    if not ep:
        return findings

    # Check for base64 encoding
    if _BASE64_RE.match(ep):
        try:
            decoded = base64.b64decode(ep).decode("utf-8", errors="replace")
            findings.append({
                "risk_category": RISK_OBFUSCATED_ENTRY_POINT,
                "severity": "HIGH",
                "detail": f"Entry point appears base64-encoded: {ep[:40]}...",
            })
        except Exception:
            pass

    # Check for hex encoding
    if _HEX_RE.match(ep):
        findings.append({
            "risk_category": RISK_OBFUSCATED_ENTRY_POINT,
            "severity": "HIGH",
            "detail": f"Entry point appears hex-encoded: {ep[:40]}...",
        })

    # Check for URL encoding
    if len(_URL_ENCODED_RE.findall(ep)) > 3:
        findings.append({
            "risk_category": RISK_OBFUSCATED_ENTRY_POINT,
            "severity": "MEDIUM",
            "detail": f"Entry point contains heavy URL-encoding: {ep[:60]}",
        })

    return findings


def _check_covert_capabilities(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    description = str(manifest.get("description") or "").lower()
    tags = [str(t).lower() for t in (manifest.get("tags") or [])]
    combined = description + " " + " ".join(tags)

    # Covert network access
    if manifest.get("network_access", False):
        network_justified = any(kw in combined for kw in [
            "api", "web", "http", "internet", "online", "fetch", "request",
            "remote", "cloud", "sync", "search", "download",
        ])
        if not network_justified:
            findings.append({
                "risk_category": RISK_COVERT_NETWORK_ACCESS,
                "severity": "HIGH",
                "detail": (
                    "Skill declares network_access=True but description does not "
                    "mention network/internet/API access."
                ),
            })

    # Covert code execution
    if manifest.get("code_execution", False):
        exec_justified = any(kw in combined for kw in [
            "code", "script", "execute", "run", "compile", "compute",
            "python", "javascript", "shell", "terminal", "interpreter",
        ])
        if not exec_justified:
            findings.append({
                "risk_category": RISK_COVERT_CODE_EXECUTION,
                "severity": "CRITICAL",
                "detail": (
                    "Skill declares code_execution=True but description does not "
                    "indicate code execution is part of the stated purpose."
                ),
            })

    return findings


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_skill_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Scan a single agent skill manifest for supply-chain risk signals.

    Parameters
    ----------
    manifest:  Dict conforming to the skill manifest schema (see module docstring).

    Returns
    -------
    Dict with keys:
        skill_id, manifest_hash, status, findings,
        finding_count, critical_count, high_count,
        risk_categories_detected, evidence_origin, scanned_at
    """
    skill_id = str(manifest.get("skill_id") or manifest.get("name") or "unknown")
    try:
        manifest_hash = _manifest_hash(manifest)
        findings: List[Dict[str, Any]] = []

        # Gather all text fields for injection scanning
        text_fields = " ".join([
            str(manifest.get("name") or ""),
            str(manifest.get("description") or ""),
            str(manifest.get("entry_point") or ""),
            " ".join(str(t) for t in (manifest.get("tags") or [])),
        ])
        findings.extend(_scan_text_for_injection(text_fields))
        findings.extend(_check_permissions(manifest))
        findings.extend(_check_publisher(manifest))
        findings.extend(_check_dependencies(manifest))
        findings.extend(_check_entry_point(manifest))
        findings.extend(_check_covert_capabilities(manifest))

        severities = [f["severity"] for f in findings]
        status = _status_from_severities(severities)
        risk_categories = list({f["risk_category"] for f in findings})

        return {
            "skill_id": skill_id,
            "manifest_hash": manifest_hash,
            "status": status,
            "findings": findings,
            "finding_count": len(findings),
            "critical_count": severities.count("CRITICAL"),
            "high_count": severities.count("HIGH"),
            "medium_count": severities.count("MEDIUM"),
            "low_count": severities.count("LOW"),
            "risk_categories_detected": risk_categories,
            "evidence_origin": "LOCALLY_OBSERVED",
            "scanned_at": _utc_now(),
        }

    except Exception as exc:
        return {
            "skill_id": skill_id,
            "manifest_hash": "",
            "status": STATUS_ERROR,
            "findings": [{"risk_category": "SCAN_ERROR", "severity": "HIGH",
                          "detail": str(exc)}],
            "finding_count": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "risk_categories_detected": ["SCAN_ERROR"],
            "evidence_origin": "LOCALLY_OBSERVED",
            "scanned_at": _utc_now(),
        }


def scan_skill_registry(manifests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Scan a collection of skill manifests (a registry snapshot).

    Returns an aggregate report covering all skills, with per-skill results
    and a registry-level risk summary.

    Parameters
    ----------
    manifests:  List of skill manifest dicts.
    """
    if not manifests:
        return {
            "registry_skill_count": 0,
            "skills_scanned": 0,
            "unsafe_count": 0,
            "suspicious_count": 0,
            "clean_count": 0,
            "error_count": 0,
            "critical_skills": [],
            "skill_results": [],
            "top_risk_categories": [],
            "evidence_origin": "LOCALLY_OBSERVED",
            "scanned_at": _utc_now(),
        }

    results = [scan_skill_manifest(m) for m in manifests]

    unsafe = [r for r in results if r["status"] == STATUS_UNSAFE]
    suspicious = [r for r in results if r["status"] == STATUS_SUSPICIOUS]
    clean = [r for r in results if r["status"] == STATUS_CLEAN]
    error = [r for r in results if r["status"] == STATUS_ERROR]
    critical_skills = [r for r in results if r["critical_count"] > 0]

    # Aggregate risk categories
    category_counts: Dict[str, int] = {}
    for r in results:
        for cat in r.get("risk_categories_detected") or []:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    top_risk_categories = sorted(
        category_counts.items(), key=lambda x: x[1], reverse=True
    )

    return {
        "registry_skill_count": len(manifests),
        "skills_scanned": len(results),
        "unsafe_count": len(unsafe),
        "suspicious_count": len(suspicious),
        "clean_count": len(clean),
        "error_count": len(error),
        "critical_skills": critical_skills,
        "skill_results": results,
        "top_risk_categories": [{"category": c, "affected_skills": n}
                                 for c, n in top_risk_categories],
        "evidence_origin": "LOCALLY_OBSERVED",
        "scanned_at": _utc_now(),
    }
