"""Registry API request/response schemas."""
from typing import Any

from pydantic import BaseModel, Field


class ModelRegistrationRequest(BaseModel):
    model_name: str
    version: str = "1.0"
    source: str
    source_url: str | None = None
    publisher: str | None = None
    license: str | None = None
    training_data: str | None = None
    dependencies: list[str] | None = None
    training_artifacts: list[str] | None = None
    deployment_pipeline: str | None = None
    metadata: dict[str, Any] | None = None


class ModelRecord(BaseModel):
    model_id: str
    model_name: str
    version: str
    source: str
    publisher: str | None = None
    sha256: str | None = None
    provenance_score: int | None = None
    risk_level: str | None = None
    registered_at: str | None = None
    metadata: dict[str, Any] | None = None


class ProvenanceAssessment(BaseModel):
    """Bounded, explainable provenance trust from the v2 provenance scorer."""

    scoring_version: str = "2.0"
    provenance_score: float | None = None
    point_estimate: float | None = None
    upper_confidence_bound: float | None = None
    confidence: float | None = None
    risk_level: str | None = None
    assessment_complete: bool | None = None
    dimensions: dict[str, Any] = Field(default_factory=dict)
    trust_caps: list[dict[str, Any]] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)


class AttestationVerification(BaseModel):
    """Registry verification evidence attached to a provenance attestation."""

    verified: bool
    checks: dict[str, bool] = Field(default_factory=dict)


class ModelAttestationResponse(BaseModel):
    """register -> attest -> verify -> rescore response payload."""

    attestation: dict[str, Any]
    verification: AttestationVerification
    provenance: ProvenanceAssessment


class VulnerabilityScanResult(BaseModel):
    """Advisory-matcher v2 scan result with bounded coverage and diagnostics."""

    scoring_version: str = "2.0"
    # VULNERABILITIES_FOUND | NO_KNOWN_VULNERABILITIES | NO_APPLICABLE_DEPENDENCIES
    # | NO_DEPENDENCIES | NO_ADVISORY_DATA | PARTIAL
    status: str
    assessment_complete: bool | None = None
    generated_at: str | None = None
    match_count: int = 0
    matches: list[dict[str, Any]] = Field(default_factory=list)
    by_severity: dict[str, int] = Field(default_factory=dict)
    coverage: dict[str, Any] = Field(default_factory=dict)
    unresolved_dependencies: list[dict[str, Any]] = Field(default_factory=list)
    indeterminate_evaluations: list[dict[str, Any]] = Field(default_factory=list)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)
    advisory_intelligence: dict[str, Any] | None = None


class MBOMRecord(BaseModel):
    model_id: str
    model_name: str
    version: str
    checksum: str | None = None
    license: str | None = None
    risk_level: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    generated_at: str | None = None
