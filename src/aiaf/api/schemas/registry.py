"""Registry API request/response schemas."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ModelRegistrationRequest(BaseModel):
    model_name: str
    version: str = "1.0"
    source: str
    source_url: Optional[str] = None
    publisher: Optional[str] = None
    license: Optional[str] = None
    training_data: Optional[str] = None
    dependencies: Optional[List[str]] = None
    training_artifacts: Optional[List[str]] = None
    deployment_pipeline: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ModelRecord(BaseModel):
    model_id: str
    model_name: str
    version: str
    source: str
    publisher: Optional[str] = None
    sha256: Optional[str] = None
    provenance_score: Optional[int] = None
    risk_level: Optional[str] = None
    registered_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ProvenanceAssessment(BaseModel):
    """Bounded, explainable provenance trust from the v2 provenance scorer."""

    scoring_version: str = "2.0"
    provenance_score: Optional[float] = None
    point_estimate: Optional[float] = None
    upper_confidence_bound: Optional[float] = None
    confidence: Optional[float] = None
    risk_level: Optional[str] = None
    assessment_complete: Optional[bool] = None
    dimensions: Dict[str, Any] = Field(default_factory=dict)
    trust_caps: List[Dict[str, Any]] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)


class AttestationVerification(BaseModel):
    """Registry verification evidence attached to a provenance attestation."""

    verified: bool
    checks: Dict[str, bool] = Field(default_factory=dict)


class ModelAttestationResponse(BaseModel):
    """register -> attest -> verify -> rescore response payload."""

    attestation: Dict[str, Any]
    verification: AttestationVerification
    provenance: ProvenanceAssessment


class VulnerabilityScanResult(BaseModel):
    """Advisory-matcher v2 scan result with bounded coverage and diagnostics."""

    scoring_version: str = "2.0"
    # VULNERABILITIES_FOUND | NO_KNOWN_VULNERABILITIES | NO_APPLICABLE_DEPENDENCIES
    # | NO_DEPENDENCIES | NO_ADVISORY_DATA | PARTIAL
    status: str
    assessment_complete: Optional[bool] = None
    generated_at: Optional[str] = None
    match_count: int = 0
    matches: List[Dict[str, Any]] = Field(default_factory=list)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    coverage: Dict[str, Any] = Field(default_factory=dict)
    unresolved_dependencies: List[Dict[str, Any]] = Field(default_factory=list)
    indeterminate_evaluations: List[Dict[str, Any]] = Field(default_factory=list)
    diagnostics: List[Dict[str, Any]] = Field(default_factory=list)
    advisory_intelligence: Optional[Dict[str, Any]] = None


class MBOMRecord(BaseModel):
    model_id: str
    model_name: str
    version: str
    checksum: Optional[str] = None
    license: Optional[str] = None
    risk_level: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    generated_at: Optional[str] = None
