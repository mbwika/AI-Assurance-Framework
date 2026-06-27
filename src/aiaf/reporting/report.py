"""Reporting helpers that aggregate findings from the datastore."""
from typing import Dict, Any


class Reporter:
    def __init__(self, datastore):
        self.datastore = datastore

    def aggregate(self, artifact_id=None) -> Dict[str, Any]:
        rows = self.datastore.list_findings(limit=1000, artifact_id=artifact_id)
        total = len(rows)
        avg_score = 0.0
        by_type = {}
        by_severity = {}
        if total > 0:
            avg_score = sum([r.get("score", 0.0) for r in rows]) / total
            for r in rows:
                for f in r.get("findings", []):
                    t = f.get("type")
                    by_type[t] = by_type.get(t, 0) + 1
                    severity = f.get("severity") or f.get("detail", {}).get("severity") or "UNKNOWN"
                    by_severity[severity] = by_severity.get(severity, 0) + 1

        return {"total_findings": total, "average_score": avg_score, "by_type": by_type, "by_severity": by_severity}
