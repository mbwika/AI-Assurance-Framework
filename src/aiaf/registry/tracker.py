"""Model source tracking utilities."""
from datetime import datetime, timezone
from typing import Dict, Any


class SourceTracker:
    def capture_source(self, model_url: str) -> Dict[str, Any]:
        # naive provider detection
        provider = "unknown"
        if "huggingface" in model_url:
            provider = "huggingface"
        elif "github.com" in model_url:
            provider = "github"
        elif "modelscope" in model_url:
            provider = "modelscope"

        parts = model_url.rstrip("/").split("/")
        organization = None
        repository = None
        if provider in ("huggingface", "github") and len(parts) >= 2:
            organization = parts[-2]
            repository = parts[-1]

        return {
            "provider": provider,
            "organization": organization,
            "repository": repository,
            "source_url": model_url,
            "retrieval_time": _utc_now(),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
