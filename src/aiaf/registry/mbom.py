"""Model Bill of Materials (MBOM) generator."""
from typing import Dict, Any, List


def generate_mbom(model_record: Dict[str, Any], dependencies: List[str] = None) -> Dict[str, Any]:
    metadata = model_record.get("metadata") or {}
    if dependencies is None:
        dependencies = model_record.get("dependencies") or metadata.get("dependencies") or []

    mbom = {
        "bom_format": "AIAF AI-BOM",
        "spec_version": "1.0",
        "serial_number": f"urn:uuid:{model_record.get('model_id')}",
        "model_id": model_record.get("model_id"),
        "model_name": model_record.get("model_name"),
        "publisher": model_record.get("publisher"),
        "version": model_record.get("version"),
        "source": model_record.get("source"),
        "source_url": model_record.get("source_url"),
        "checksum": model_record.get("sha256"),
        "dependencies": dependencies,
        "training_data": model_record.get("training_data"),
        "training_artifacts": model_record.get("training_artifacts") or metadata.get("training_artifacts") or [],
        "deployment_pipeline": model_record.get("deployment_pipeline") or metadata.get("deployment_pipeline") or {},
        "license": model_record.get("license"),
        "provenance_score": model_record.get("provenance_score"),
        "risk_level": model_record.get("risk_level"),
        "dependency_discovery": metadata.get("dependency_discovery", {}),
        "vulnerability_scan": model_record.get("vulnerability_scan")
        or metadata.get("vulnerability_scan", {}),
    }
    return mbom
