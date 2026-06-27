import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


class _ConcurrencyCheckedCursor:
    def __init__(self, connection):
        self.connection = connection
        self._rows = []

    def execute(self, query, params=None):
        if not self.connection.query_gate.acquire(blocking=False):
            raise sqlite3.InterfaceError("simulated concurrent sqlite misuse")
        self.connection.executions.append((query, params))
        time.sleep(0.01)
        if "FROM models" in query:
            self._rows = [
                {
                    "model_id": "model-1",
                    "model_name": "Demo",
                    "version": "1.0",
                    "source": "huggingface",
                    "source_url": "https://huggingface.co/acme/demo",
                    "publisher": "Acme",
                    "sha256": "a" * 64,
                    "registered_by": "alice",
                    "provenance_score": 80,
                    "risk_level": "LOW",
                    "metadata_json": "{}",
                    "created_at": "2026-06-22T00:00:00Z",
                }
            ]
        else:
            self._rows = [
                {
                    "id": 1,
                    "artifact_id": "model-1",
                    "metric_name": "risk_score",
                    "metric_value": 4.0,
                    "dimensions_json": '{"artifact_id": "model-1"}',
                    "created_at": "2026-06-22T00:00:00Z",
                }
            ]
        return self

    def fetchall(self):
        rows = self._rows
        self.connection.query_gate.release()
        return rows


class _ConcurrencyCheckedConnection:
    def __init__(self):
        self.executions = []
        self.query_gate = threading.Lock()

    def cursor(self):
        return _ConcurrencyCheckedCursor(self)

    def close(self):
        return None


def test_sqlite_store_serializes_shared_connection_reads():
    ensure_src()
    from aiaf.data.store import DataStore

    store = DataStore.__new__(DataStore)
    store._conn = _ConcurrencyCheckedConnection()
    store._conn_lock = threading.RLock()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = []
        for _ in range(10):
            futures.append(pool.submit(store.list_models, 50, None))
            futures.append(pool.submit(store.list_metrics, 50, None))

        results = [future.result() for future in futures]

    assert len(results) == 20
    assert all(result for result in results)
