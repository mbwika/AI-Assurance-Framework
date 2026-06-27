"""Governance control evidence submission and independent review workflow."""

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from ..mapping.control_catalog import get_control_catalog

EVIDENCE_TYPES = {
    "ATTESTATION",
    "CONFIGURATION",
    "DOCUMENT",
    "METRIC",
    "TEST_RESULT",
}
EVIDENCE_STATUSES = {"PENDING", "APPROVED", "REJECTED"}


class GovernanceEvidenceEngine:
    def __init__(self, datastore: object):
        self.datastore = datastore

    def submit(
        self,
        *,
        artifact_id: str,
        control_id: str,
        evidence_fields: list[str],
        evidence_type: str,
        reference: str,
        sha256: str,
        submitted_by: str,
        expires_at: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        artifact_id = str(artifact_id or "").strip()
        submitted_by = str(submitted_by or "").strip()
        reference = str(reference or "").strip()
        if not artifact_id:
            raise ValueError("artifact_id is required")
        if not submitted_by:
            raise ValueError("submitted_by is required")
        if not reference:
            raise ValueError("reference is required")
        digest = str(sha256 or "").lower()
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")

        control = _control(control_id)
        requested_fields = sorted(
            {str(field).strip() for field in evidence_fields if str(field).strip()}
        )
        valid_fields = set(control.get("evidence_fields", [])) | set(
            control.get("evidence_fields_any", [])
        )
        if not requested_fields:
            raise ValueError("At least one evidence field is required")
        invalid = sorted(set(requested_fields) - valid_fields)
        if invalid:
            raise ValueError(
                f"Evidence fields are not valid for {control_id}: {invalid}"
            )

        normalized_type = str(evidence_type or "").upper()
        if normalized_type not in EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type: {evidence_type}")
        now = _utc_now()
        expiration = _normalize_datetime(expires_at) if expires_at else None
        if expiration and expiration <= now:
            raise ValueError("expires_at must be in the future")

        evidence = {
            "id": str(uuid.uuid4()),
            "artifact_id": artifact_id,
            "control_id": control_id,
            "evidence_fields": requested_fields,
            "evidence_type": normalized_type,
            "reference": reference,
            "sha256": digest,
            "metadata": metadata or {},
            "submitted_by": submitted_by,
            "submitted_at": now,
            "expires_at": expiration,
            "status": "PENDING",
            "reviewer": None,
            "review_rationale": None,
            "reviewed_at": None,
            "updated_at": now,
        }
        self.datastore.save_control_evidence(evidence)
        self.datastore.save_audit_log(
            {
                "event_type": "control_evidence_submitted",
                "artifact_id": artifact_id,
                "details": {
                    "evidence_id": evidence["id"],
                    "control_id": control_id,
                    "evidence_fields": requested_fields,
                    "sha256": digest,
                    "submitted_by": submitted_by,
                },
            }
        )
        self._record_pending_metric()
        return evidence

    def review(
        self,
        evidence_id: str,
        *,
        decision: str,
        reviewer: str,
        rationale: str,
    ) -> dict[str, Any] | None:
        evidence = self.datastore.get_control_evidence(evidence_id)
        if not evidence:
            return None
        if evidence["status"] != "PENDING":
            raise ValueError("Only PENDING evidence can be reviewed")
        reviewer = str(reviewer or "").strip()
        rationale = str(rationale or "").strip()
        if not reviewer:
            raise ValueError("reviewer is required")
        if reviewer.casefold() == str(evidence["submitted_by"]).casefold():
            raise ValueError("Evidence submitters cannot review their own evidence")
        if not rationale:
            raise ValueError("review rationale is required")
        status = str(decision or "").upper()
        if status not in {"APPROVED", "REJECTED"}:
            raise ValueError("decision must be APPROVED or REJECTED")
        now = _utc_now()
        if status == "APPROVED" and _is_expired(evidence, now):
            raise ValueError("Expired evidence cannot be approved")

        updated = self.datastore.review_control_evidence(
            evidence_id,
            {
                "status": status,
                "reviewer": reviewer,
                "review_rationale": rationale,
                "reviewed_at": now,
                "updated_at": now,
            },
        )
        if updated is None:
            raise ValueError("Evidence was reviewed concurrently; reload its current state")
        self.datastore.save_audit_log(
            {
                "event_type": "control_evidence_reviewed",
                "artifact_id": evidence["artifact_id"],
                "details": {
                    "evidence_id": evidence_id,
                    "control_id": evidence["control_id"],
                    "decision": status,
                    "reviewer": reviewer,
                    "rationale": rationale,
                },
            }
        )
        self._record_pending_metric()
        return updated

    def list(
        self,
        limit: int = 1000,
        artifact_id: str | None = None,
        control_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        normalized_status = None
        if status:
            normalized_status = str(status).upper()
            if normalized_status not in EVIDENCE_STATUSES:
                raise ValueError(f"Invalid evidence status: {status}")
        return self.datastore.list_control_evidence(
            limit=min(max(int(limit), 1), 10000),
            artifact_id=artifact_id,
            control_id=control_id,
            status=normalized_status,
        )

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        return self.datastore.get_control_evidence(evidence_id)

    def summary(self, as_of: str | None = None) -> dict[str, Any]:
        evaluated_at = _normalize_datetime(as_of) if as_of else _utc_now()
        evidence = self.datastore.list_control_evidence(limit=100000)
        return evidence_summary(evidence, evaluated_at)

    def _record_pending_metric(self) -> None:
        pending = len(self.datastore.list_control_evidence(limit=100000, status="PENDING"))
        self.datastore.save_metric("pending_control_evidence", pending, {})


def evidence_summary(
    evidence: list[dict[str, Any]], as_of: str | None = None
) -> dict[str, Any]:
    evaluated_at = _normalize_datetime(as_of) if as_of else _utc_now()
    expired = [item for item in evidence if _is_expired(item, evaluated_at)]
    return {
        "evaluated_at": evaluated_at,
        "total_evidence": len(evidence),
        "pending_evidence": sum(1 for item in evidence if item["status"] == "PENDING"),
        "approved_evidence": sum(1 for item in evidence if item["status"] == "APPROVED"),
        "rejected_evidence": sum(1 for item in evidence if item["status"] == "REJECTED"),
        "expired_evidence": len(expired),
        "expired_approved_evidence": sum(
            1 for item in expired if item["status"] == "APPROVED"
        ),
        "by_control": _count_by(evidence, "control_id"),
        "by_type": _count_by(evidence, "evidence_type"),
    }


def approved_evidence(
    evidence: list[dict[str, Any]], as_of: str | None = None
) -> list[dict[str, Any]]:
    evaluated_at = _normalize_datetime(as_of) if as_of else _utc_now()
    return [
        item
        for item in evidence
        if item.get("status") == "APPROVED" and not _is_expired(item, evaluated_at)
    ]


def _control(control_id: str) -> dict[str, Any]:
    for control in get_control_catalog():
        if control["id"] == control_id:
            return control
    raise ValueError(f"Unknown control_id: {control_id}")


def _is_expired(evidence: dict[str, Any], as_of: str) -> bool:
    return bool(evidence.get("expires_at") and evidence["expires_at"] <= as_of)


def _normalize_datetime(value: Any) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid datetime: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _count_by(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(field) or "UNKNOWN")
        counts[value] = counts.get(value, 0) + 1
    return counts
