"""Data model for ModelRecord and related helpers."""
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ModelRecord:
    model_id: str
    model_name: str
    version: str
    source: str
    source_url: str
    publisher: str | None
    sha256: str
    uploaded_at: str
    registered_by: str | None
    license: str | None
    training_data: str | None
    dependencies: list[Any] = field(default_factory=list)
    training_artifacts: list[dict[str, Any]] = field(default_factory=list)
    deployment_pipeline: dict[str, Any] = field(default_factory=dict)
    provenance_score: int | None = None
    risk_level: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        model_name: str,
        version: str,
        source: str,
        source_url: str,
        sha256: str,
        publisher: str | None = None,
        registered_by: str | None = None,
        license: str | None = None,
        training_data: str | None = None,
        dependencies: list[Any] | None = None,
        training_artifacts: list[dict[str, Any]] | None = None,
        deployment_pipeline: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
