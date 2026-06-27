"""Lightweight in-process metrics registry.

Counters and histograms are accumulated in-memory.  When ``prometheus_client``
is installed the same values can be scraped via a /metrics endpoint; without
it the registry's ``snapshot()`` method exposes raw aggregates for the
reporting layer.
"""


class _Counter:
    __slots__ = ("_value",)

    def __init__(self) -> None:
        self._value: float = 0.0

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    @property
    def value(self) -> float:
        return self._value


class _Histogram:
    _DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self) -> None:
        self._buckets = self._DEFAULT_BUCKETS
        self._counts: dict[float, int] = {b: 0 for b in self._buckets}
        self._total: float = 0.0
        self._count: int = 0

    def observe(self, value: float) -> None:
        self._total += value
        self._count += 1
        for b in self._buckets:
            if value <= b:
                self._counts[b] += 1


class MetricsRegistry:
    def __init__(self) -> None:
        self._counters: dict[str, _Counter] = {}
        self._histograms: dict[str, _Histogram] = {}

    def counter(self, name: str) -> _Counter:
        if name not in self._counters:
            self._counters[name] = _Counter()
        return self._counters[name]

    def histogram(self, name: str) -> _Histogram:
        if name not in self._histograms:
            self._histograms[name] = _Histogram()
        return self._histograms[name]

    def snapshot(self) -> dict:
        return {
            "counters": {k: v.value for k, v in self._counters.items()},
            "histograms": {
                k: {"count": v._count, "sum": v._total}
                for k, v in self._histograms.items()
            },
        }


registry = MetricsRegistry()


def record_analysis_duration(analyzer: str, duration_seconds: float) -> None:
    registry.histogram("aiaf_analysis_duration_seconds").observe(duration_seconds)
    registry.counter(f"aiaf_analysis_{analyzer}_total").inc()


def record_api_request(method: str, path: str, status_code: int) -> None:
    registry.counter("aiaf_api_requests_total").inc()
    if status_code >= 500:
        registry.counter("aiaf_api_errors_total").inc()
