"""RAG Security Analyser.

Detects three classes of threat in RAG pipeline traffic:

1. **Indirect prompt injection** — adversarial instructions embedded in
   retrieved documents that target the LLM reading them.

2. **Sensitive-data leakage** — PII or credentials surfacing in retrieved
   chunks, indicating the document store contains data that should not be
   retrievable in this context.

3. **Trust-mix violations** — retrieved chunks whose trust labels span
   a range that violates the minimum required trust level for the query,
   meaning unverified or adversarial documents are silently mixed with
   trusted sources.

All evidence is ``LOCALLY_OBSERVED`` — findings are derived from scanning
the text of chunks, not from operator claims.

Content privacy
---------------
The raw text of chunks is used *only* for pattern matching and is never
persisted.  ``content_hash`` (SHA-256) is stored in findings instead.

Evidence model
--------------
Returned dicts carry ``evidence_origin = "LOCALLY_OBSERVED"``, finding
severities, and standards references (OWASP-LLM01, AML.T0051, etc.) so
findings can be imported directly into the AIAF evidence ledger.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

SCAN_VERSION = "1.0"

# ── Status constants ──────────────────────────────────────────────────────────

STATUS_CLEAN = "CLEAN"
STATUS_SUSPICIOUS = "SUSPICIOUS"           # MEDIUM-severity injection hints
STATUS_INJECTION_DETECTED = "INJECTION_DETECTED"  # HIGH/CRITICAL injection
STATUS_LEAKAGE_DETECTED = "LEAKAGE_DETECTED"      # PII/credentials in chunks
STATUS_TRUST_VIOLATION = "TRUST_VIOLATION"         # mixed/low trust labels

_STATUS_RANK: dict[str, int] = {
    STATUS_CLEAN: 0,
    STATUS_SUSPICIOUS: 1,
    STATUS_TRUST_VIOLATION: 2,
    STATUS_LEAKAGE_DETECTED: 3,
    STATUS_INJECTION_DETECTED: 4,
}

# ── Trust label rank (imported pattern mirrors rag_inventory constants) ────────

_TRUST_RANK: dict[str, int] = {
    "VERIFIED": 5,
    "INTERNAL": 4,
    "EXTERNAL": 3,
    "USER_GENERATED": 2,
    "UNTRUSTED": 1,
}

# ── Pattern tables ────────────────────────────────────────────────────────────
# Each entry: (compiled_regex, severity, finding_type, refs)

_RAG_INJECTION_PATTERNS: list[tuple[re.Pattern, str, str, list[str]]] = [
    # ── Direct AI addressing embedded in a document ───────────────────────
    (re.compile(
        r"(?:note\s+to|attention|for)\s+(?:the\s+)?(?:ai|llm|assistant|chatbot|gpt|claude|gemini)\b",
        re.I),
     "CRITICAL", "rag_direct_ai_addressing", ["OWASP-LLM01", "AML.T0051"]),

    # ── Retrieval-triggered instructions ─────────────────────────────────
    (re.compile(
        r"(?:when|upon|after)\s+(?:this\s+(?:is|has\s+been|gets)\s+)?(?:retrieved|fetched|"
        r"read\s+by\s+(?:an?\s+)?(?:ai|llm|assistant))",
        re.I),
     "HIGH", "rag_retrieval_triggered_instruction", ["OWASP-LLM01", "AML.T0051"]),

    # ── Context / instruction override ───────────────────────────────────
    (re.compile(
        r"(?:this\s+(?:document\s+)?(?:overrides?|supersedes?|replaces?|takes?\s+precedence\s+over))"
        r".{0,40}?(?:instructions?|context|rules?|constraints?)",
        re.I | re.S),
     "CRITICAL", "rag_context_override", ["OWASP-LLM01", "AML.T0051"]),

    # ── HTML / markdown comment injection ────────────────────────────────
    (re.compile(
        r"<!--\s*(?:ai|system|assistant|llm|gpt|note\s+to\s+(?:ai|assistant)|instruction)",
        re.I),
     "HIGH", "rag_comment_injection", ["OWASP-LLM01", "AML.T0051"]),

    # ── Zero-width / invisible character instruction hiding ───────────────
    (re.compile(r"[​‌‍﻿]{3,}"),
     "HIGH", "rag_hidden_characters", ["OWASP-LLM01", "AML.T0051"]),

    # ── Pre-answer side-channel tool-call instruction ─────────────────────
    (re.compile(
        r"before\s+(?:you\s+)?(?:answer|respond|reply|output).{0,80}"
        r"(?:first\s+)?(?:call|invoke|run|execute|send|use).{0,40}?"
        r"(?:\btool\b|\bfunction\b|\bapi\b|\bwebhook\b|\bendpoint\b)",
        re.I | re.S),
     "HIGH", "rag_side_channel_tool_call", ["OWASP-LLM01", "AML.T0051"]),

    # ── Standard ignore-instructions (also valid in RAG context) ─────────
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
     "CRITICAL", "injection_instruction_override", ["OWASP-LLM01", "AML.T0051"]),

    (re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+instructions?", re.I),
     "CRITICAL", "injection_instruction_override", ["OWASP-LLM01", "AML.T0051"]),

    # ── Token injection artifacts ─────────────────────────────────────────
    (re.compile(r"<\|im_start\|>|<\|system\|>|<\|endoftext\|>|<\|end\|>", re.I),
     "CRITICAL", "injection_token_injection", ["OWASP-LLM01", "AML.T0051"]),

    (re.compile(r"<tools?-override>|<inject>|<system-prompt>", re.I),
     "CRITICAL", "injection_token_injection", ["OWASP-LLM01", "AML.T0051"]),

    # ── Role / system block injection ─────────────────────────────────────
    (re.compile(r"\[system\]\s*:|\[INST\]|###\s*system\s*:", re.I),
     "HIGH", "injection_role_injection", ["OWASP-LLM01", "AML.T0051"]),

    # ── Exfiltration instruction ──────────────────────────────────────────
    (re.compile(
        r"(exfiltrate|exfil|leak|transmit)\s+(all\s+)?(the\s+)?"
        r"(data|files?|secrets?|tokens?|credentials?|conversation)",
        re.I),
     "CRITICAL", "injection_data_exfil", ["OWASP-LLM02", "AML.T0024"]),

    # ── Subtle persona / role manipulation ───────────────────────────────
    (re.compile(r"you\s+are\s+now\s+(a|an|the)\b", re.I),
     "MEDIUM", "injection_persona_override", ["OWASP-LLM01", "AML.T0051"]),

    (re.compile(r"from\s+now\s+on\s+(you\s+)?(are|will\s+\w+|must)", re.I),
     "MEDIUM", "injection_persona_override", ["OWASP-LLM01", "AML.T0051"]),
]

# PII / leakage patterns — reused structure, tagged as leakage findings
_LEAKAGE_PATTERNS: list[tuple[re.Pattern, str, str, list[str]]] = [
    (re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
     "LOW", "leakage_pii_email", ["OWASP-LLM02"]),
    (re.compile(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
     "LOW", "leakage_pii_phone", ["OWASP-LLM02"]),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
     "MEDIUM", "leakage_pii_ssn", ["OWASP-LLM02"]),
    (re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
     "MEDIUM", "leakage_pii_credit_card", ["OWASP-LLM02"]),
    (re.compile(
        r"\b(password|passwd|secret|api[_\-]?key|access[_\-]?token)\s*[=:]\s*\S+", re.I),
     "HIGH", "leakage_credential_exposure", ["OWASP-LLM02", "AML.T0024"]),
    (re.compile(
        r"\b(private[_\-]?key|client[_\-]?secret|bearer\s+[a-z0-9_\.\-]{20,})", re.I),
     "HIGH", "leakage_credential_exposure", ["OWASP-LLM02", "AML.T0024"]),
]

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_BLOCK_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso8601(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _worst_status(a: str, b: str) -> str:
    return a if _STATUS_RANK.get(a, 0) >= _STATUS_RANK.get(b, 0) else b


def _by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        result[sev] = result.get(sev, 0) + 1
    return result


def _by_type(findings: list[dict[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for f in findings:
        ft = f.get("type", "unknown")
        result[ft] = result.get(ft, 0) + 1
    return result


def _scan_content(content: str, patterns: list[tuple], dedup: set | None = None) -> list[dict[str, Any]]:
    """Scan ``content`` against ``patterns`` (regex, severity, type, refs).

    ``dedup`` set prevents duplicate finding types within a single chunk.
    """
    findings = []
    seen: set = dedup if dedup is not None else set()
    for regex, severity, ptype, refs in patterns:
        if ptype in seen:
            continue
        m = regex.search(content)
        if m:
            findings.append({
                "type": ptype,
                "severity": severity,
                "match_excerpt": m.group(0)[:120],
                "refs": refs,
                "evidence_origin": "LOCALLY_OBSERVED",
            })
            seen.add(ptype)
    return findings


def _injection_status_from_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return STATUS_CLEAN
    severities = {f["severity"] for f in findings}
    if severities & _BLOCK_SEVERITIES:
        return STATUS_INJECTION_DETECTED
    return STATUS_SUSPICIOUS


def _leakage_status_from_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return STATUS_CLEAN
    return STATUS_LEAKAGE_DETECTED


def _check_trust_violations(
    chunks: list[dict[str, Any]],
    minimum_trust_label: str | None = None,
) -> tuple[bool, list[dict[str, Any]]]:
    """Return ``(violation_found, trust_findings)``."""
    findings = []
    min_rank = _TRUST_RANK.get(str(minimum_trust_label or "").upper(), 0)
    lowest_rank = 5
    labels_seen = set()

    for i, chunk in enumerate(chunks):
        tl = str(chunk.get("trust_label") or "").upper()
        rank = _TRUST_RANK.get(tl, 0)
        if rank > 0:
            labels_seen.add(tl)
            if rank < lowest_rank:
                lowest_rank = rank

        # UNTRUSTED is always flagged — adversarial content is plausible
        if tl == "UNTRUSTED":
            findings.append({
                "type": "untrusted_chunk",
                "severity": "HIGH",
                "chunk_index": i,
                "doc_id": chunk.get("doc_id"),
                "chunk_trust_label": tl,
                "refs": ["OWASP-LLM01"],
                "evidence_origin": "LOCALLY_OBSERVED",
            })
        # Any label below the caller's minimum trust threshold
        elif min_rank > 0 and rank > 0 and rank < min_rank:
            findings.append({
                "type": "trust_label_violation",
                "severity": "HIGH" if rank <= 1 else "MEDIUM",
                "chunk_index": i,
                "doc_id": chunk.get("doc_id"),
                "chunk_trust_label": tl,
                "required_minimum": minimum_trust_label,
                "refs": ["OWASP-LLM01"],
                "evidence_origin": "LOCALLY_OBSERVED",
            })

    # Mixed trust: UNTRUSTED/USER_GENERATED mixed with VERIFIED/INTERNAL
    if len(labels_seen) >= 2:
        high_trust = labels_seen & {"VERIFIED", "INTERNAL"}
        low_trust = labels_seen & {"USER_GENERATED", "UNTRUSTED"}
        if high_trust and low_trust:
            findings.append({
                "type": "trust_mix_violation",
                "severity": "MEDIUM",
                "labels_seen": sorted(labels_seen),
                "refs": ["OWASP-LLM01"],
                "evidence_origin": "LOCALLY_OBSERVED",
            })

    return bool(findings), findings


# ── Public API ────────────────────────────────────────────────────────────────

def scan_chunks(
    chunks: list[dict[str, Any]],
    *,
    minimum_trust_label: str | None = None,
    scan_for_leakage: bool = True,
) -> dict[str, Any]:
    """Scan a list of retrieved RAG chunks for security findings.

    Parameters
    ----------
    chunks:
        List of chunk dicts.  Each must have ``content`` (str).  Optional
        keys: ``doc_id``, ``trust_label``, ``metadata``.
    minimum_trust_label:
        If provided, any chunk whose trust label ranks below this level
        generates a trust-violation finding.  Values: ``"VERIFIED"``,
        ``"INTERNAL"``, ``"EXTERNAL"``, ``"USER_GENERATED"``, ``"UNTRUSTED"``.
    scan_for_leakage:
        If ``True`` (default), PII / credential patterns are applied to chunk
        content to detect sensitive-data leakage from the vector store.

    Returns
    -------
    Dict with keys:
        ``scan_version``, ``status``, ``finding_count``, ``findings``,
        ``by_severity``, ``by_finding_type``, ``chunk_count``,
        ``affected_chunks`` (list of indices with findings),
        ``trust_summary``, ``trust_violation``,
        ``evidence_origin``, ``scanned_at``.
    """
    all_findings: list[dict[str, Any]] = []
    affected_chunks: list[int] = []
    trust_summary: dict[str, int] = {}
    status = STATUS_CLEAN

    for idx, chunk in enumerate(chunks):
        content = str(chunk.get("content") or "")
        tl = str(chunk.get("trust_label") or "").upper()
        if tl:
            trust_summary[tl] = trust_summary.get(tl, 0) + 1

        chunk_dedup: set = set()
        chunk_findings: list[dict[str, Any]] = []

        # 1. Indirect prompt injection
        inj = _scan_content(content, _RAG_INJECTION_PATTERNS, chunk_dedup)
        if inj:
            for f in inj:
                f["chunk_index"] = idx
                f["doc_id"] = chunk.get("doc_id")
                f["content_hash"] = _sha256(content)
            chunk_findings.extend(inj)
            status = _worst_status(status, _injection_status_from_findings(inj))

        # 2. Sensitive-data leakage
        if scan_for_leakage:
            leak_dedup: set = set()
            leak = _scan_content(content, _LEAKAGE_PATTERNS, leak_dedup)
            if leak:
                for f in leak:
                    f["chunk_index"] = idx
                    f["doc_id"] = chunk.get("doc_id")
                    f["content_hash"] = _sha256(content)
                chunk_findings.extend(leak)
                status = _worst_status(status, _leakage_status_from_findings(leak))

        if chunk_findings:
            all_findings.extend(chunk_findings)
            affected_chunks.append(idx)

    # 3. Trust-mix / label violations (cross-chunk)
    trust_violated, trust_findings = _check_trust_violations(chunks, minimum_trust_label)
    if trust_findings:
        all_findings.extend(trust_findings)
        if trust_violated:
            status = _worst_status(status, STATUS_TRUST_VIOLATION)

    all_findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.get("severity", "LOW"), 0))

    return {
        "scan_version": SCAN_VERSION,
        "status": status,
        "finding_count": len(all_findings),
        "findings": all_findings,
        "by_severity": _by_severity(all_findings),
        "by_finding_type": _by_type(all_findings),
        "chunk_count": len(chunks),
        "affected_chunks": affected_chunks,
        "trust_summary": trust_summary,
        "trust_violation": trust_violated,
        "evidence_origin": "LOCALLY_OBSERVED",
        "scanned_at": _utc_now(),
    }


def scan_document_for_ingestion(
    content: str,
    trust_label: str,
    *,
    doc_id: str | None = None,
    scan_for_leakage: bool = True,
) -> dict[str, Any]:
    """Scan a document before it is ingested into a vector store.

    This is a pre-ingestion gate: if the document contains injection patterns
    it should either be rejected or downgraded to ``UNTRUSTED``.

    Parameters
    ----------
    content:
        Full document text.  Used only for scanning — never persisted.
    trust_label:
        Trust label the caller intends to assign this document.
    doc_id:
        Optional document identifier (echoed in findings).
    scan_for_leakage:
        If ``True`` (default), also check whether the document contains PII
        or credentials that should not enter the vector store.

    Returns
    -------
    Dict with keys:
        ``scan_version``, ``status``, ``doc_id``, ``content_hash``,
        ``trust_label``, ``finding_count``, ``findings``, ``by_severity``,
        ``evidence_origin``, ``scanned_at``.
    """
    content_hash = _sha256(content)
    findings: list[dict[str, Any]] = []
    dedup: set = set()
    status = STATUS_CLEAN

    # Injection scan
    inj = _scan_content(content, _RAG_INJECTION_PATTERNS, dedup)
    if inj:
        findings.extend(inj)
        status = _worst_status(status, _injection_status_from_findings(inj))

    # Leakage scan
    if scan_for_leakage:
        leak_dedup: set = set()
        leak = _scan_content(content, _LEAKAGE_PATTERNS, leak_dedup)
        if leak:
            findings.extend(leak)
            status = _worst_status(status, _leakage_status_from_findings(leak))

    findings.sort(key=lambda f: -_SEVERITY_RANK.get(f.get("severity", "LOW"), 0))

    return {
        "scan_version": SCAN_VERSION,
        "status": status,
        "doc_id": doc_id,
        "content_hash": content_hash,
        "trust_label": str(trust_label).upper(),
        "finding_count": len(findings),
        "findings": findings,
        "by_severity": _by_severity(findings),
        "evidence_origin": "LOCALLY_OBSERVED",
        "scanned_at": _utc_now(),
    }


def assess_store_security(
    store_id: str,
    inventory_store: Any,
) -> dict[str, Any]:
    """Compute a security posture summary for a registered vector store.

    Parameters
    ----------
    store_id:
        Store ID to assess (must be registered in the inventory).
    inventory_store:
        AIAF model store.

    Returns
    -------
    Dict with keys:
        ``store_id``, ``status``, ``document_count``,
        ``trust_distribution``, ``unscanned_count``,
        ``vulnerable_count`` (docs with injection scan findings),
        ``high_risk_count``, ``low_trust_count``, ``finding_summary``,
        ``evidence_origin``, ``assessed_at``.
    """
    from ..registry.rag_inventory import get_vector_store, list_documents

    rec = get_vector_store(store_id, inventory_store)
    if rec is None:
        return {
            "store_id": store_id,
            "status": "NOT_FOUND",
            "error": f"Vector store '{store_id}' not found in inventory.",
            "assessed_at": _utc_now(),
        }

    full_record = inventory_store.get_model(f"rag_store:{store_id}") or {}
    metadata = full_record.get("metadata") or {}

    docs, total = list_documents(store_id, inventory_store, limit=MAX_DOCS_PER_ASSESS)
    status = STATUS_CLEAN
    unscanned = 0
    vulnerable = 0
    high_risk = 0
    low_trust = 0
    trust_dist: dict[str, int] = {}
    backend_findings: list[dict[str, Any]] = []

    for doc in docs:
        tl = doc.get("trust_label", "")
        if tl:
            trust_dist[tl] = trust_dist.get(tl, 0) + 1
        if tl in ("USER_GENERATED", "UNTRUSTED"):
            low_trust += 1

        scan_status = doc.get("scan_status")
        doc.get("scan_finding_count", 0)
        if scan_status is None:
            unscanned += 1
        elif scan_status == STATUS_INJECTION_DETECTED:
            vulnerable += 1
            high_risk += 1
        elif scan_status in (STATUS_LEAKAGE_DETECTED, STATUS_SUSPICIOUS):
            vulnerable += 1

    if high_risk > 0:
        status = STATUS_INJECTION_DETECTED
    elif vulnerable > 0 or unscanned > (total // 2 if total else 0):
        status = STATUS_SUSPICIOUS
    elif low_trust > 0:
        status = STATUS_TRUST_VIOLATION

    access_mode = str(metadata.get("access_control_mode") or "UNKNOWN").upper()
    if access_mode == "OPEN":
        backend_findings.append({
            "type": "store_access_control_open",
            "severity": "HIGH",
            "detail": "Vector store access controls are declared OPEN; retrieval exposure is not bounded.",
            "refs": ["OWASP-LLM08"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })
    elif access_mode == "SHARED":
        backend_findings.append({
            "type": "store_access_control_shared",
            "severity": "MEDIUM",
            "detail": "Vector store access controls are shared across tenants or teams without explicit review evidence.",
            "refs": ["OWASP-LLM08"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })
    elif access_mode == "UNKNOWN":
        backend_findings.append({
            "type": "store_access_control_unknown",
            "severity": "MEDIUM",
            "detail": "No vector store access-control posture was declared.",
            "refs": ["OWASP-LLM08"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })

    tenant_isolation = metadata.get("tenant_isolation")
    if tenant_isolation is False:
        backend_findings.append({
            "type": "store_tenant_isolation_absent",
            "severity": "HIGH",
            "detail": "Tenant or collection isolation is declared absent, increasing cross-context retrieval risk.",
            "refs": ["OWASP-LLM08"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })

    freshness_sla_hours = metadata.get("freshness_sla_hours")
    last_indexed_at = _parse_iso8601(metadata.get("last_indexed_at"))
    if freshness_sla_hours and last_indexed_at is not None:
        age_hours = (datetime.now(timezone.utc) - last_indexed_at).total_seconds() / 3600.0
        if age_hours > float(freshness_sla_hours):
            backend_findings.append({
                "type": "store_index_stale",
                "severity": "MEDIUM",
                "detail": (
                    f"Vector index age {age_hours:.1f}h exceeds freshness SLA "
                    f"{freshness_sla_hours}h."
                ),
                "refs": ["OWASP-LLM08"],
                "evidence_origin": "LOCALLY_OBSERVED",
            })
    elif freshness_sla_hours and last_indexed_at is None:
        backend_findings.append({
            "type": "store_index_freshness_unknown",
            "severity": "MEDIUM",
            "detail": "Freshness SLA was declared but last_indexed_at is missing, so stale-index risk cannot be bounded.",
            "refs": ["OWASP-LLM08"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })

    embedding_verified = metadata.get("embedding_verified")
    embedding_source_trust = str(metadata.get("embedding_source_trust") or "").upper()
    if embedding_verified is False:
        backend_findings.append({
            "type": "embedding_provenance_unverified",
            "severity": "MEDIUM",
            "detail": "Embedding provenance is explicitly unverified.",
            "refs": ["OWASP-LLM08", "OWASP-LLM03"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })
    elif embedding_verified is None and not embedding_source_trust:
        backend_findings.append({
            "type": "embedding_provenance_unknown",
            "severity": "MEDIUM",
            "detail": "No embedding provenance or trust declaration was recorded for this vector store.",
            "refs": ["OWASP-LLM08", "OWASP-LLM03"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })
    elif embedding_source_trust in {"USER_GENERATED", "UNTRUSTED"}:
        backend_findings.append({
            "type": "embedding_source_low_trust",
            "severity": "HIGH" if embedding_source_trust == "UNTRUSTED" else "MEDIUM",
            "detail": (
                f"Embedding source trust is {embedding_source_trust}, increasing retrieval-manipulation risk."
            ),
            "refs": ["OWASP-LLM08"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })

    pii_screening_enabled = metadata.get("pii_screening_enabled")
    if pii_screening_enabled is False:
        backend_findings.append({
            "type": "pii_screening_disabled",
            "severity": "MEDIUM",
            "detail": "PII/credential screening is declared disabled for this retrieval pipeline.",
            "refs": ["OWASP-LLM02", "OWASP-LLM08"],
            "evidence_origin": "LOCALLY_OBSERVED",
        })

    if any(item.get("severity") in {"CRITICAL", "HIGH"} for item in backend_findings):
        status = _worst_status(status, STATUS_INJECTION_DETECTED)
    elif backend_findings:
        status = _worst_status(status, STATUS_SUSPICIOUS)

    return {
        "store_id": store_id,
        "status": status,
        "document_count": total,
        "trust_distribution": trust_dist,
        "unscanned_count": unscanned,
        "vulnerable_count": vulnerable,
        "high_risk_count": high_risk,
        "low_trust_count": low_trust,
        "default_trust_label": rec.get("default_trust_label"),
        "backend_finding_count": len(backend_findings),
        "backend_findings": backend_findings,
        "backend_security_profile": {
            "access_control_mode": access_mode,
            "tenant_isolation": tenant_isolation,
            "last_indexed_at": metadata.get("last_indexed_at"),
            "freshness_sla_hours": freshness_sla_hours,
            "embedding_source_url": metadata.get("embedding_source_url"),
            "embedding_source_trust": metadata.get("embedding_source_trust"),
            "embedding_verified": embedding_verified,
            "pii_screening_enabled": pii_screening_enabled,
        },
        "finding_summary": {
            "injection_detected_docs": high_risk,
            "leakage_or_suspicious_docs": vulnerable - high_risk,
            "unscanned_docs": unscanned,
            "low_trust_docs": low_trust,
            "backend_findings": len(backend_findings),
        },
        "evidence_origin": "LOCALLY_OBSERVED",
        "assessed_at": _utc_now(),
    }


# Max documents to iterate in assess_store_security (pagination guard)
MAX_DOCS_PER_ASSESS = 500
