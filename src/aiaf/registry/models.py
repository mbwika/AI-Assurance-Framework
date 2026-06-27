"""Data model for ModelRecord and related helpers."""
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import uuid


@dataclass
class ModelRecord:
    model_id: str
    model_name: str
    version: str
    source: str
    source_url: str
    publisher: Optional[str]
    sha256: str
    uploaded_at: str
    registered_by: Optional[str]
    license: Optional[str]
    training_data: Optional[str]
    dependencies: List[Any] = field(default_factory=list)
    training_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    deployment_pipeline: Dict[str, Any] = field(default_factory=dict)
    provenance_score: Optional[int] = None
    risk_level: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        model_name: str,
        version: str,
        source: str,
        source_url: str,
        sha256: str,
        publisher: Optional[str] = None,
        registered_by: Optional[str] = None,
        license: Optional[str] = None,
        training_data: Optional[str] = None,
        dependencies: Optional[List[Any]] = None,
        training_artifacts: Optional[List[Dict[str, Any]]] = None,
        deployment_pipeline: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        if metadata is None:
            metadata = {}
        return cls(
            model_id=str(uuid.uuid4()),
            model_name=model_name,
            version=version,
            source=source,
            source_url=source_url,
            publisher=publisher,
            sha256=sha256,
            uploaded_at=_utc_now(),
            registered_by=registered_by,
            license=license,
            training_data=training_data,
            dependencies=dependencies or [],
            training_artifacts=training_artifacts or [],
            deployment_pipeline=deployment_pipeline or {},
            metadata=metadata,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
