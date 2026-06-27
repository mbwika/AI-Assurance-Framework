"""Abstract base classes for AIAF analyzer and mapping plugins.

Third-party analyzers subclass ``AnalyzerPlugin`` and are discovered
automatically by the plugin loader.  Compliance framework mappers subclass
``MappingPlugin``.

Example
-------
    class MyCustomAnalyzer(AnalyzerPlugin):
        name = "my_custom_analyzer"

        def analyze(self, context):
            return {"findings": [], "score": 0.0}
"""
from abc import ABC, abstractmethod
from typing import Any


class AnalyzerPlugin(ABC):
    """Base class for custom security analyzer plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique kebab-case plugin identifier."""

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return ""

    @abstractmethod
    def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        """Run analysis and return a findings dict.

        The dict must contain at least::

            {
                "findings": [{"type": str, "severity": str, "detail": str}],
                "score": float,          # 0–10
            }
        """


class MappingPlugin(ABC):
    """Base class for compliance framework mapping plugins."""

    @property
    @abstractmethod
    def framework_id(self) -> str:
        """Unique uppercase framework ID, e.g. ``"EU_AI_ACT"``."""

    @property
    @abstractmethod
    def framework_name(self) -> str:
        """Human-readable name, e.g. ``"EU AI Act (2024/1689)"``."""

    @abstractmethod
    def map_finding(self, finding: dict[str, Any]) -> list[str]:
        """Map a finding to one or more control / article references.

        Returns a list of string references, e.g. ``["Article 9", "Article 13"]``.
        """
