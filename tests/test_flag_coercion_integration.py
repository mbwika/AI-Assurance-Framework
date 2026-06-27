"""Regression tests for artifact boolean-flag coercion in the risk engine.

JSON/form artifacts can carry boolean evidence flags as strings. ``bool("false")``
is truthy, which previously granted evaluation credit the artifact never claimed.
The engine now parses flags with ``_flag`` so "false" reaches the analyzers as
False.
"""
import sys
from pathlib import Path


def ensure_src():
    root = Path(__file__).resolve().parents[1]
    src = str(root / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def test_flag_parser_handles_strings_bools_and_defaults():
    ensure_src()
    from aiaf.core.risk_engine import _flag

    for falsy in ("false", "False", "FALSE", "0", "no", "off", "disabled", ""):
        assert _flag(falsy) is False
    for truthy in ("true", "True", "1", "yes", "on", "enabled"):
        assert _flag(truthy) is True
    assert _flag(True) is True
    assert _flag(False) is False
    assert _flag(None) is False
    assert _flag(None, default=True) is True
    # Unrecognized values fall back to the default (conservative for evidence).
    assert _flag("maybe") is False
    assert _flag("maybe", default=True) is True
    assert _flag(1) is True
    assert _flag(0) is False


def test_string_false_evidence_flags_do_not_grant_credit(tmp_path):
    ensure_src()
    from aiaf.core import RiskEngine
    from aiaf.data.store import DataStore

    store = DataStore(db_path=str(tmp_path / "flags.db"))
    record = RiskEngine(datastore=store).analyze(
        {
            "id": "flag-model",
            "content": "benign",
            "domain": "hiring",
            "model_risk_profile": {"impact_level": "high"},
            # Declared as the STRING "false" — must not count as real evidence.
            "has_bias_evaluation": "false",
            "has_fairness_metrics": "false",
            "has_factuality_evaluation": "false",
            "has_output_grounding": "false",
        }
    )
    by_type = {finding["type"]: finding for finding in record["findings"]}

    # The analyzers must see the flags as False and flag the missing evidence.
    assert "no_bias_evaluation" in by_type["bias_fairness"]["detail"]["indicators"]
    hallucination_factors = {
        factor["factor"]
        for factor in by_type["hallucination_risk"]["detail"]["risk_factors"]
    }
    assert "no_factuality_evaluation" in hallucination_factors
