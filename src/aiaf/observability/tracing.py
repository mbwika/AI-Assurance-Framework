"""OpenTelemetry tracing stub.

When ``opentelemetry-sdk`` is installed and ``AIAF_TRACING_ENABLED=true`` is
set, configure the SDK here.  The no-op tracer keeps the rest of the codebase
instrumentation-ready without a hard dependency on the OTel packages.
"""
from collections.abc import Generator
from contextlib import contextmanager


class _NoopSpan:
    def set_attribute(self, key: str, value: object) -> None:  # noqa: ARG002
        pass

    def record_exception(self, exc: Exception) -> None:  # noqa: ARG002
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class _NoopTracer:
    @contextmanager
    def start_as_current_span(self, name: str, **_kwargs) -> Generator[_NoopSpan, None, None]:
        yield _NoopSpan()


_tracer: _NoopTracer = _NoopTracer()


def get_tracer(name: str = "aiaf") -> _NoopTracer:
    return _tracer


def configure_tracing(service_name: str = "aiaf", otlp_endpoint: str | None = None) -> None:
    """Wire up the OTel SDK when the package is available."""
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider()
        if otlp_endpoint:
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
        trace.set_tracer_provider(provider)
    except ImportError:
        pass
