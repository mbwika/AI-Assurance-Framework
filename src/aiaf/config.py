"""Centralized runtime configuration for the AI Assurance Framework.

All knobs are resolved from environment variables so the application can be
deployed without code changes.  Import ``settings`` for the singleton instance.
"""
import os


class Settings:
    # ── API ──────────────────────────────────────────────────────────────────
    api_host: str = os.getenv("AIAF_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("AIAF_PORT", "8000"))
    api_key: str | None = os.getenv("AIAF_API_KEY")
    api_version: str = os.getenv("AIAF_API_VERSION", "0.2.0")

    # ── Persistence ───────────────────────────────────────────────────────────
    pg_dsn: str | None = os.getenv("AIAF_PG_DSN")
    sqlite_path: str = os.getenv("AIAF_SQLITE_PATH", "data/aiaf.db")
    vector_store_path: str = os.getenv("AIAF_VECTOR_STORE_PATH", "data/vectors")

    # ── Signing keys ──────────────────────────────────────────────────────────
    attestation_key: str | None = os.getenv("AIAF_ATTESTATION_KEY")
    attestation_key_id: str = os.getenv("AIAF_ATTESTATION_KEY_ID", "default")
    advisory_feed_key: str | None = os.getenv("AIAF_ADVISORY_FEED_KEY")
    advisory_feed_key_id: str = os.getenv("AIAF_ADVISORY_FEED_KEY_ID", "default")
    report_signing_key: str | None = os.getenv("AIAF_REPORT_SIGNING_KEY")
    report_signing_key_id: str = os.getenv("AIAF_REPORT_SIGNING_KEY_ID", "default")

    # ── Observability ─────────────────────────────────────────────────────────
    log_level: str = os.getenv("AIAF_LOG_LEVEL", "INFO")
    log_format: str = os.getenv("AIAF_LOG_FORMAT", "json")   # "json" | "text"
    metrics_enabled: bool = os.getenv("AIAF_METRICS_ENABLED", "false").lower() == "true"
    tracing_enabled: bool = os.getenv("AIAF_TRACING_ENABLED", "false").lower() == "true"
    otlp_endpoint: str | None = os.getenv("AIAF_OTLP_ENDPOINT")

    # ── Notifications ─────────────────────────────────────────────────────────
    webhook_url: str | None = os.getenv("AIAF_WEBHOOK_URL")
    webhook_secret: str | None = os.getenv("AIAF_WEBHOOK_SECRET")
    slack_webhook_url: str | None = os.getenv("AIAF_SLACK_WEBHOOK_URL")

    # ── Plugin system ─────────────────────────────────────────────────────────
    plugin_dir: str | None = os.getenv("AIAF_PLUGIN_DIR")

    # ── Monitoring worker ─────────────────────────────────────────────────────
    monitor_poll_seconds: int = int(os.getenv("AIAF_MONITOR_POLL_SECONDS", "60"))

    # ── Export formats ────────────────────────────────────────────────────────
    sarif_tool_version: str = os.getenv("AIAF_SARIF_TOOL_VERSION", "0.2.0")


settings = Settings()
