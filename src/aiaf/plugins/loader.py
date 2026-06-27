"""Plugin discovery and loading for the AI Assurance Framework.

Plugins are plain Python modules placed in the directory pointed to by
``AIAF_PLUGIN_DIR``.  Any class that is a concrete subclass of
``AnalyzerPlugin`` or ``MappingPlugin`` is instantiated and registered.

Call ``load_plugins(plugin_dir)`` once at application startup.
"""
import importlib.util
import os
import pkgutil
from typing import List, Optional

from .base import AnalyzerPlugin, MappingPlugin

_analyzer_plugins: List[AnalyzerPlugin] = []
_mapping_plugins: List[MappingPlugin] = []
_loaded = False


def load_plugins(plugin_dir: Optional[str] = None) -> None:
    """Discover and register plugins from *plugin_dir*."""
    global _loaded
    if _loaded:
        return
    _loaded = True

    if not plugin_dir or not os.path.isdir(plugin_dir):
        return

    for finder, name, _ in pkgutil.iter_modules([plugin_dir]):
        spec = finder.find_spec(name)  # type: ignore[union-attr]
        if spec is None or spec.loader is None:
            continue
        try:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception:
            continue
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if not isinstance(obj, type):
                continue
            try:
                if issubclass(obj, AnalyzerPlugin) and obj is not AnalyzerPlugin:
                    _analyzer_plugins.append(obj())
                elif issubclass(obj, MappingPlugin) and obj is not MappingPlugin:
                    _mapping_plugins.append(obj())
            except Exception:
                pass


def get_analyzer_plugins() -> List[AnalyzerPlugin]:
    return list(_analyzer_plugins)


def get_mapping_plugins() -> List[MappingPlugin]:
    return list(_mapping_plugins)


def registered_plugin_names() -> dict:
    return {
        "analyzers": [p.name for p in _analyzer_plugins],
        "mappings": [p.framework_id for p in _mapping_plugins],
    }
