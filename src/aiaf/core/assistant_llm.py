"""Optional LLM-backed intent resolution for the AIAF assistant."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from .assistant_prompts import ASSISTANT_MODE, SUPPORTED_INTENTS, SYSTEM_CONTRACT

logger = logging.getLogger(__name__)

_ALLOWED_INTENTS = frozenset(SUPPORTED_INTENTS)


class AssistantLLMIntentResolver:
    """Resolve assistant intent through an OpenAI-compatible chat endpoint."""

    def __init__(
        self,
        *,
        endpoint_url: str | None = None,
        api_key: str | None = None,
        model_name: str | None = None,
        timeout: float = 20.0,
        http_client: Any = None,
    ):
        self.endpoint_url = str(endpoint_url or os.getenv("AIAF_ASSISTANT_ENDPOINT_URL") or "").strip()
        self.api_key = str(api_key or os.getenv("AIAF_ASSISTANT_ENDPOINT_API_KEY") or "").strip() or None
        self.model_name = str(model_name or os.getenv("AIAF_ASSISTANT_MODEL_NAME") or "default").strip()
        self.timeout = float(timeout)
        self.http_client = http_client

    def configured(self) -> bool:
        return bool(self.endpoint_url)

    def metadata(self) -> dict[str, Any]:
        return {
            "mode": f"{ASSISTANT_MODE}+llm-intent" if self.configured() else ASSISTANT_MODE,
            "llm_intent_enabled": self.configured(),
            "llm_model_name": self.model_name if self.configured() else None,
            "llm_endpoint_configured": bool(self.endpoint_url),
        }

    def resolve(
        self,
        *,
        message: str,
        scope_hint: dict[str, Any] | None = None,
        supported_intents: list[str] | None = None,
    ) -> dict[str, Any] | None:
        if not self.configured():
            return None

        payload = {
            "model": self.model_name,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        f"{SYSTEM_CONTRACT} "
                        "Classify the user's AIAF request into one supported intent and optional scope hint. "
                        "Return strict JSON with keys: intent, scope, clarification_question, reasoning. "
                        "Only use supported intents."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "message": message,
                            "scope_hint": scope_hint or {},
                            "supported_intents": supported_intents or list(SUPPORTED_INTENTS),
                            "write_actions_enabled": ["create_report_snapshot"],
                        }
                    ),
                },
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        client = self.http_client or httpx.Client()
        close_client = self.http_client is None
        try:
            base = self.endpoint_url.rstrip("/")
            if base.endswith("/v1"):
                base = base[: -len("/v1")]
            url = base + "/v1/chat/completions"
            response = client.post(url, json=payload, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            body = response.json()
            content = (((body.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
            parsed = json.loads(content) if content else {}
            return self._normalize_result(parsed)
        except Exception as exc:
            logger.warning("Assistant LLM intent resolution failed; falling back to deterministic mode: %s", exc)
            return None
        finally:
            if close_client:
                try:
                    client.close()
                except Exception:
                    pass

    def _normalize_result(self, parsed: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(parsed, dict):
            return None
        intent = str(parsed.get("intent") or "").strip()
        if intent and intent not in _ALLOWED_INTENTS:
            return None
        scope = parsed.get("scope") if isinstance(parsed.get("scope"), dict) else {}
        normalized_scope = {
            "artifact_id": _normalize(scope.get("artifact_id")),
            "model_id": _normalize(scope.get("model_id")),
            "registered_by": _normalize(scope.get("registered_by")),
        }
        selected = [name for name, value in normalized_scope.items() if value]
        if len(selected) > 1:
            return {
                "intent": "help",
                "scope": normalized_scope,
                "clarification_question": "I found multiple scopes. Please choose one of artifact, model, or registrant.",
                "source": "llm",
            }
        clarification = _normalize(parsed.get("clarification_question"))
        return {
            "intent": intent or "help",
            "scope": normalized_scope,
            "clarification_question": clarification,
            "source": "llm",
            "reasoning": _normalize(parsed.get("reasoning")),
        }


def _normalize(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None
