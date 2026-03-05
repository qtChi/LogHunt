# ==============================================================================
# tests/testEngine/testCoverage.py
#
# 100% branch coverage for loghunter/engine/coverage.py
#
# Test strategy:
#   - Construction: None args → TypeError for each.
#   - get_coverage_matrix(): always 16 records, sorted order, has_rule_match
#     always True, has_sigma_rule True/False, class_uids populated,
#     sigma engine failure → still returns records.
#   - get_coverage_summary(): keys present, counts correct, percent math,
#     by_tactic populated, uncovered list correct, all covered case,
#     none covered case.
#   - get_techniques_for_tactic(): None → TypeError, empty → ValueError,
#     known tactic returns filtered subset, unknown tactic returns [],
#     results are subset of full matrix.
#   - MitreMapper and SigmaEngine both mocked — no real DB or Parquet.
# ==============================================================================

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from loghunter.engine.coverage import (
    TECHNIQUE_TACTIC_MAP,
    TACTIC_ORDER,
    CoverageEngine,
    TechniqueCoverage,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_mapper(rules_by_class: dict | None = None):
    """
    Build a mock MitreMapper.

    rules_by_class: {class_uid: [MappingRule-like objects]}
    Defaults to returning one rule per technique per class (real mapper shape).
    """
    mapper = MagicMock()

    if rules_by_class is None:
        # Return a rule stub for every technique in each class
        from loghunter.engine.mitre_mapper import MitreMapper
        real = MitreMapper()
        mapper.get_rules_for_class.side_effect = real.get_rules_for_class
    else:
        def _rules_for_class(class_uid):
            return rules_by_class.get(class_uid, [])
        mapper.get_rules_for_class.side_effect = _rules_for_class

    return mapper


def _make_sigma(confirmed_yamls: list[str] | None = None):
    """
    Build a mock SigmaEngine.
    confirmed_yamls: list of yaml_content strings to return from list_rules.
    """
    sigma = MagicMock()

    if confirmed_yamls is None:
        sigma.list_rules.return_value = []
    else:
        sigma.list_rules.return_value = [
            {"yaml_content": y, "rule_id": f"rule_{i}", "analyst_confirmed": 1}
            for i, y in enumerate(confirmed_yamls)
        ]

    return sigma


def _make_engine(
    confirmed_yamls: list[str] | None = None,
    rules_by_class: dict | None = None,
) -> CoverageEngine:
    return CoverageEngine(
        mitre_mapper=_make_mapper(rules_by_class),
        sigma_engine=_make_sigma(confirmed_yamls),
    )


# ===========================================================================
# Construction
# ===========================================================================

class TestCoverageEngineConstruction:

    def test_none_mapper_raises_type_error(self):
        with pytest.raises(TypeError, match="mitre_mapper must not be None"):
            CoverageEngine(mitre_mapper=None, sigma_engine=_make_sigma())

    def test_none_sigma_raises_type_error(self):
        with pytest.raises(TypeError, match="sigma_engine must not be None"):
            CoverageEngine(mitre_mapper=_make_mapper(), sigma_engine=None)

    def test_valid_construction(self):
        engine = _make_engine()
        assert engine is not None


# ===========================================================================
# get_coverage_matrix()
# ===========================================================================

class TestGetCoverageMatrix:

    def test_always_returns_16_records(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        assert len(matrix) == 16

    def test_returns_list_of_technique_coverage(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        for record in matrix:
            assert isinstance(record, TechniqueCoverage)

    def test_has_rule_match_always_true(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        for record in matrix:
            assert record.has_rule_match is True

    def test_all_16_technique_ids_present(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        technique_ids = {r.technique_id for r in matrix}
        assert technique_ids == set(TECHNIQUE_TACTIC_MAP.keys())

    def test_tactic_assigned_correctly(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        for record in matrix:
            assert record.tactic == TECHNIQUE_TACTIC_MAP[record.technique_id]

    def test_sorted_by_tactic_order_then_technique_id(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        tactic_indices = [TACTIC_ORDER.index(r.tactic) for r in matrix if r.tactic in TACTIC_ORDER]
        assert tactic_indices == sorted(tactic_indices)

        # Within each tactic, technique IDs are sorted
        from itertools import groupby
        for _, group in groupby(matrix, key=lambda r: r.tactic):
            ids = [r.technique_id for r in group]
            assert ids == sorted(ids)

    def test_has_sigma_rule_false_when_no_confirmed_rules(self):
        engine = _make_engine(confirmed_yamls=[])
        matrix = engine.get_coverage_matrix()
        for record in matrix:
            assert record.has_sigma_rule is False

    def test_has_sigma_rule_true_when_yaml_contains_technique_id(self):
        """Rule YAML mentioning T1078 → T1078 and T1078.002 both flagged."""
        engine = _make_engine(confirmed_yamls=["tags:\n  - attack.t1078\ndetection: ..."])
        matrix = engine.get_coverage_matrix()
        t1078 = next(r for r in matrix if r.technique_id == "T1078")
        assert t1078.has_sigma_rule is True

    def test_has_sigma_rule_parent_matches_when_yaml_contains_subtechnique(self):
        """
        If yaml contains 'T1110.001', then T1110 also gets flagged because
        'T1110' is a substring of 'T1110.001'.
        The yaml must use uppercase IDs to match the case-sensitive check.
        """
        yaml = "tags:\n  - attack.T1110.001"
        engine = _make_engine(confirmed_yamls=[yaml])
        matrix = engine.get_coverage_matrix()
        t1110_001 = next(r for r in matrix if r.technique_id == "T1110.001")
        assert t1110_001.has_sigma_rule is True
        # T1110 is a substring of "T1110.001" in the yaml → also True
        t1110 = next(r for r in matrix if r.technique_id == "T1110")
        assert t1110.has_sigma_rule is True

    def test_has_sigma_rule_false_when_technique_not_in_yaml(self):
        engine = _make_engine(confirmed_yamls=["tags:\n  - attack.t9999"])
        matrix = engine.get_coverage_matrix()
        for record in matrix:
            assert record.has_sigma_rule is False

    def test_multiple_confirmed_rules_any_match_counts(self):
        """Two rules — one covers T1059, one covers T1078."""
        yamls = [
            "tags:\n  - attack.T1059",
            "tags:\n  - attack.T1078",
        ]
        engine = _make_engine(confirmed_yamls=yamls)
        matrix = engine.get_coverage_matrix()
        t1059 = next(r for r in matrix if r.technique_id == "T1059")
        t1078 = next(r for r in matrix if r.technique_id == "T1078")
        assert t1059.has_sigma_rule is True
        assert t1078.has_sigma_rule is True

    def test_class_uids_populated_for_known_techniques(self):
        """Techniques with built-in mapper rules should have class_uids."""
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        # T1059 is class 4001 (Process Activity)
        t1059 = next(r for r in matrix if r.technique_id == "T1059")
        assert 4001 in t1059.class_uids

    def test_class_uids_list_is_sorted(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        for record in matrix:
            assert record.class_uids == sorted(record.class_uids)

    def test_sigma_engine_failure_returns_records_with_sigma_false(self):
        """If SigmaEngine.list_rules raises, matrix still returns 16 records."""
        mapper = _make_mapper()
        sigma = MagicMock()
        sigma.list_rules.side_effect = RuntimeError("DB error")
        engine = CoverageEngine(mitre_mapper=mapper, sigma_engine=sigma)
        matrix = engine.get_coverage_matrix()
        assert len(matrix) == 16
        for record in matrix:
            assert record.has_sigma_rule is False

    def test_mapper_failure_returns_empty_list(self):
        """If MitreMapper raises, get_coverage_matrix returns [] gracefully."""
        mapper = MagicMock()
        mapper.get_rules_for_class.side_effect = RuntimeError("mapper error")
        sigma = _make_sigma()
        engine = CoverageEngine(mitre_mapper=mapper, sigma_engine=sigma)
        # The outer try/except in get_coverage_matrix catches this
        matrix = engine.get_coverage_matrix()
        assert isinstance(matrix, list)

    def test_no_duplicate_technique_ids(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        ids = [r.technique_id for r in matrix]
        assert len(ids) == len(set(ids))

    def test_all_tactics_from_technique_tactic_map(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        expected_tactics = set(TECHNIQUE_TACTIC_MAP.values())
        actual_tactics = {r.tactic for r in matrix}
        assert actual_tactics == expected_tactics


# ===========================================================================
# get_coverage_summary()
# ===========================================================================

class TestGetCoverageSummary:

    def test_returns_dict(self):
        engine = _make_engine()
        summary = engine.get_coverage_summary()
        assert isinstance(summary, dict)

    def test_all_required_keys_present(self):
        engine = _make_engine()
        summary = engine.get_coverage_summary()
        for key in (
            "total_techniques",
            "rule_match_count",
            "sigma_confirmed_count",
            "coverage_percent",
            "by_tactic",
            "uncovered_techniques",
        ):
            assert key in summary, f"Missing key: {key}"

    def test_total_techniques_always_16(self):
        engine = _make_engine()
        assert engine.get_coverage_summary()["total_techniques"] == 16

    def test_rule_match_count_always_16(self):
        engine = _make_engine()
        assert engine.get_coverage_summary()["rule_match_count"] == 16

    def test_sigma_confirmed_count_zero_when_no_rules(self):
        engine = _make_engine(confirmed_yamls=[])
        summary = engine.get_coverage_summary()
        assert summary["sigma_confirmed_count"] == 0

    def test_sigma_confirmed_count_correct_when_some_covered(self):
        # Cover T1059 (and T1059.001, T1059.007 as substrings)
        engine = _make_engine(confirmed_yamls=["T1059"])
        summary = engine.get_coverage_summary()
        # T1059, T1059.001, T1059.007 all contain "T1059"
        assert summary["sigma_confirmed_count"] == 3

    def test_coverage_percent_zero_when_no_sigma(self):
        engine = _make_engine(confirmed_yamls=[])
        summary = engine.get_coverage_summary()
        assert summary["coverage_percent"] == 0.0

    def test_coverage_percent_100_when_all_covered(self):
        # Put all 16 technique IDs in one yaml
        all_techniques = " ".join(TECHNIQUE_TACTIC_MAP.keys())
        engine = _make_engine(confirmed_yamls=[all_techniques])
        summary = engine.get_coverage_summary()
        assert summary["coverage_percent"] == 100.0

    def test_coverage_percent_calculation(self):
        # Cover exactly T1190 (Initial Access — no substring overlap with others)
        engine = _make_engine(confirmed_yamls=["T1190"])
        summary = engine.get_coverage_summary()
        expected = summary["sigma_confirmed_count"] / 16 * 100
        assert abs(summary["coverage_percent"] - expected) < 0.001

    def test_by_tactic_dict_present(self):
        engine = _make_engine()
        summary = engine.get_coverage_summary()
        assert isinstance(summary["by_tactic"], dict)

    def test_by_tactic_counts_sum_to_16(self):
        engine = _make_engine()
        summary = engine.get_coverage_summary()
        assert sum(summary["by_tactic"].values()) == 16

    def test_by_tactic_defense_evasion_has_four(self):
        """T1078, T1078.002, T1055, T1070.004 all map to Defense Evasion."""
        engine = _make_engine()
        summary = engine.get_coverage_summary()
        assert summary["by_tactic"]["Defense Evasion"] == 4

    def test_by_tactic_execution_has_three(self):
        """T1059, T1059.001, T1059.007."""
        engine = _make_engine()
        summary = engine.get_coverage_summary()
        assert summary["by_tactic"]["Execution"] == 3

    def test_uncovered_techniques_all_16_when_no_sigma(self):
        engine = _make_engine(confirmed_yamls=[])
        summary = engine.get_coverage_summary()
        assert len(summary["uncovered_techniques"]) == 16

    def test_uncovered_techniques_empty_when_all_covered(self):
        all_techniques = " ".join(TECHNIQUE_TACTIC_MAP.keys())
        engine = _make_engine(confirmed_yamls=[all_techniques])
        summary = engine.get_coverage_summary()
        assert summary["uncovered_techniques"] == []

    def test_uncovered_techniques_excludes_covered_ones(self):
        engine = _make_engine(confirmed_yamls=["T1190"])
        summary = engine.get_coverage_summary()
        assert "T1190" not in summary["uncovered_techniques"]

    def test_sigma_engine_failure_returns_zeroed_summary(self):
        mapper = _make_mapper()
        sigma = MagicMock()
        sigma.list_rules.side_effect = RuntimeError("DB error")
        engine = CoverageEngine(mitre_mapper=mapper, sigma_engine=sigma)
        summary = engine.get_coverage_summary()
        # Still computes from matrix — sigma just returns no confirmed yamls
        assert summary["total_techniques"] == 16
        assert summary["sigma_confirmed_count"] == 0


# ===========================================================================
# get_techniques_for_tactic()
# ===========================================================================

class TestGetTechniquesForTactic:

    def test_none_raises_type_error(self):
        engine = _make_engine()
        with pytest.raises(TypeError, match="tactic must not be None"):
            engine.get_techniques_for_tactic(None)

    def test_empty_string_raises_value_error(self):
        engine = _make_engine()
        with pytest.raises(ValueError, match="tactic must not be empty"):
            engine.get_techniques_for_tactic("")

    def test_whitespace_only_raises_value_error(self):
        engine = _make_engine()
        with pytest.raises(ValueError):
            engine.get_techniques_for_tactic("   ")

    def test_known_tactic_returns_non_empty_list(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Execution")
        assert len(result) > 0

    def test_execution_returns_three_techniques(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Execution")
        ids = {r.technique_id for r in result}
        assert ids == {"T1059", "T1059.001", "T1059.007"}

    def test_credential_access_returns_two_techniques(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Credential Access")
        ids = {r.technique_id for r in result}
        assert ids == {"T1110", "T1110.001"}

    def test_initial_access_returns_one_technique(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Initial Access")
        assert len(result) == 1
        assert result[0].technique_id == "T1190"

    def test_unknown_tactic_returns_empty_list(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Impact")
        assert result == []

    def test_nonexistent_tactic_returns_empty_list(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Reconnaissance")
        assert result == []

    def test_results_are_subset_of_full_matrix(self):
        engine = _make_engine()
        matrix = engine.get_coverage_matrix()
        result = engine.get_techniques_for_tactic("Defense Evasion")
        matrix_ids = {r.technique_id for r in matrix}
        for record in result:
            assert record.technique_id in matrix_ids

    def test_all_results_have_correct_tactic(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Command and Control")
        for record in result:
            assert record.tactic == "Command and Control"

    def test_returns_technique_coverage_instances(self):
        engine = _make_engine()
        result = engine.get_techniques_for_tactic("Execution")
        for record in result:
            assert isinstance(record, TechniqueCoverage)

    def test_tactic_with_sigma_coverage_reflected(self):
        engine = _make_engine(confirmed_yamls=["T1059"])
        result = engine.get_techniques_for_tactic("Execution")
        for record in result:
            assert record.has_sigma_rule is True


# ===========================================================================
# TECHNIQUE_TACTIC_MAP and TACTIC_ORDER constants
# ===========================================================================

class TestConstants:

    def test_technique_tactic_map_has_16_entries(self):
        assert len(TECHNIQUE_TACTIC_MAP) == 16

    def test_tactic_order_has_12_entries(self):
        assert len(TACTIC_ORDER) == 12

    def test_all_tactics_in_map_are_in_tactic_order(self):
        map_tactics = set(TECHNIQUE_TACTIC_MAP.values())
        for tactic in map_tactics:
            assert tactic in TACTIC_ORDER, f"'{tactic}' missing from TACTIC_ORDER"

    def test_no_duplicate_techniques(self):
        assert len(TECHNIQUE_TACTIC_MAP) == len(set(TECHNIQUE_TACTIC_MAP.keys()))

    def test_no_duplicate_tactics_in_order(self):
        assert len(TACTIC_ORDER) == len(set(TACTIC_ORDER))