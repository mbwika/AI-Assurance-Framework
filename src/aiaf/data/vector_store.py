"""Local vector database abstraction for development and tests."""
import math
from typing import Any, Dict, List, Optional


class InMemoryVectorStore:
    """Small vector store used as a development stand-in for a managed vector DB."""

    def __init__(self):
        self._vectors: Dict[str, Dict[str, Any]] = {}

    def upsert(self, vector_id: str, embedding: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        self._vectors[vector_id] = {"embedding": [float(v) for v in embedding], "metadata": metadata or {}}

    def query(self, embedding: List[float], limit: int = 5) -> List[Dict[str, Any]]:
        query_vector = [float(v) for v in embedding]
        scored = []
        for vector_id, record in self._vectors.items():
            score = _cosine_similarity(query_vector, record["embedding"])
            scored.append({"id": vector_id, "score": score, "metadata": record["metadata"]})
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:limit]

    def count(self) -> int:
        return len(self._vectors)


def _cosine_similarity(left: List[float], right: List[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)
