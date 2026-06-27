"""HTTP webhook notifier for AIAF alerts, findings, and risk events.

The notifier is intentionally dependency-free (stdlib only) so it works in
any deployment without additional packages.  An HMAC-SHA256 ``X-AIAF-Signature``
header is added when a ``secret`` is configured, allowing receivers to verify
that the payload originated from this installation.
"""
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from typing import Any

from ..observability.logging import get_logger

logger = get_logger(__name__)


class WebhookNotifier:
    def __init__(
        self,
        url: str,
        secret: str | None = None,
        timeout: int = 10,
    ) -> None:
        self._url = url
        self._secret = secret
        self._timeout = timeout

    def send(self, event_type: str, payload: dict[str, Any]) -> bool:
        """POST an event to the configured webhook URL.

        Returns True when the remote responded with a 2xx status code.
        """
        body = json.dumps({"event_type": event_type, "payload": payload}).encode()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._secret:
            sig = hmac.new(self._secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-AIAF-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                success = 200 <= resp.status < 300
                if not success:
                    logger.warning(
                        "webhook delivery non-2xx status=%d url=%s event=%s",
                        resp.status, self._url, event_type,
                    )
                return success
        except urllib.error.URLError as exc:
            logger.warning(
                "webhook delivery failed: %s url=%s event=%s", exc, self._url, event_type
            )
            return False


def notify_critical_finding(
    notifier: WebhookNotifier | None,
    finding_type: str,
    artifact_id: str | None,
    details: dict[str, Any],
) -> None:
    """Fire-and-forget critical finding notification; safe when notifier is None."""
    if notifier is None:
        return
    notifier.send(
        "critical_finding",
        {"finding_type": finding_type, "artifact_id": artifact_id, **details},
    )
