import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.fci_engine import FCIEngine  # noqa: E402


@pytest.fixture
def engine():
    return FCIEngine()


def test_empty_input_is_low_risk(engine):
    result = engine.calculate({})
    # Only the neutral consistency score (0.5 * 0.10) contributes.
    assert result["confidence_score"] == pytest.approx(0.05)
    assert result["risk_level"] == "Low"


def test_all_maxed_components_is_high_risk(engine):
    result = engine.calculate({
        "rule_analysis": {
            "rule_score": 1.0,
            "flagged_entities": [{"type": "user", "value": "Alice"}],
        },
        "anomaly_analysis": {"overall_anomaly_score": 1.0, "flagged_users": ["alice"]},
        "graph_analysis": {"central_nodes": [{"centrality_score": 0.9}]},
        "similarity_analysis": {"similarity_score": 1.0},
    })
    assert result["confidence_score"] == pytest.approx(1.0)
    assert result["risk_level"] == "High"


def test_centrality_is_scaled_and_capped(engine):
    assert engine._calculate_centrality_component({}) == 0.0
    assert engine._calculate_centrality_component(
        {"central_nodes": [{"centrality_score": 0.1}, {"centrality_score": 0.3}]}
    ) == pytest.approx(0.4)
    assert engine._calculate_centrality_component(
        {"central_nodes": [{"centrality_score": 0.9}]}
    ) == 1.0


def test_consistency_scores(engine):
    neutral = engine._calculate_consistency_score({})
    one_sided = engine._calculate_consistency_score(
        {"anomaly_analysis": {"flagged_users": ["bob"]}}
    )
    disjoint = engine._calculate_consistency_score({
        "rule_analysis": {"flagged_entities": [{"type": "user", "value": "a"}]},
        "anomaly_analysis": {"flagged_users": ["b"]},
    })
    full_overlap = engine._calculate_consistency_score({
        "rule_analysis": {"flagged_entities": [{"type": "user", "value": "A"}]},
        "anomaly_analysis": {"flagged_users": ["a"]},
    })
    assert (neutral, one_sided, disjoint, full_overlap) == (0.5, 0.4, 0.5, 1.0)


def test_non_user_entities_are_ignored_for_consistency(engine):
    score = engine._calculate_consistency_score({
        "rule_analysis": {"flagged_entities": [{"type": "ip", "value": "1.2.3.4"}]},
        "anomaly_analysis": {"flagged_users": ["a"]},
    })
    assert score == 0.4


@pytest.mark.parametrize("fci,components,expected", [
    (0.7, {}, "High"),
    (0.1, {"a": 0.7, "b": 0.8, "c": 0.9}, "High"),
    (0.4, {}, "Medium"),
    (0.1, {"a": 0.7}, "Medium"),
    (0.39, {"a": 0.6}, "Low"),  # 0.6 is not strictly greater than the cut-off
])
def test_risk_level_thresholds(engine, fci, components, expected):
    assert engine._determine_risk_level(fci, components) == expected


def test_breakdown_handles_zero_fci(engine):
    breakdown = engine._generate_breakdown(0.0, {"rule_score": 0.5})
    assert breakdown["rule_score"]["percentage_of_fci"] == 0
    assert breakdown["anomaly_score"]["raw_score"] == 0


def test_compare_cases(engine):
    assert engine.compare_cases([]) == {"comparison": "No cases to compare"}
    result = engine.compare_cases([
        {"confidence_score": 0.2, "risk_level": "Low"},
        {"confidence_score": 0.8, "risk_level": "High"},
    ])
    assert result["average_fci"] == 0.5
    assert result["highest_fci"] == 0.8
    assert result["lowest_fci"] == 0.2
    assert (result["high_risk_count"], result["medium_risk_count"], result["low_risk_count"]) == (1, 0, 1)
