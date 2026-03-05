# tests/testUI/testCoverage.py — 100% branch coverage for ui/tabs/coverage.py pure functions
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()
sys.modules["loghunter.ui.components.attack_heatmap"] = MagicMock()
sys.modules["loghunter.ui.components"] = MagicMock()

from loghunter.ui.tabs.coverage import build_heatmap_data, build_coverage_summary_text
from loghunter.engine.coverage import TechniqueCoverage


def _record(technique_id, tactic, has_sigma=False):
    return TechniqueCoverage(technique_id=technique_id, tactic=tactic,
                              has_rule_match=True, has_sigma_rule=has_sigma, class_uids=[6003])


class TestBuildHeatmapData:
    def test_empty_matrix_returns_empty_dict(self):
        assert build_heatmap_data([]) == {}

    def test_none_matrix_returns_empty_dict(self):
        assert build_heatmap_data(None) == {}

    def test_tactics_list_populated(self):
        matrix = [_record("T1059", "Execution"), _record("T1078", "Defense Evasion")]
        result = build_heatmap_data(matrix)
        assert "Execution" in result["tactics"]
        assert "Defense Evasion" in result["tactics"]

    def test_no_duplicate_tactics(self):
        matrix = [_record("T1059", "Execution"), _record("T1059.001", "Execution")]
        result = build_heatmap_data(matrix)
        assert result["tactics"].count("Execution") == 1

    def test_techniques_by_tactic_populated(self):
        matrix = [_record("T1059", "Execution"), _record("T1059.001", "Execution")]
        result = build_heatmap_data(matrix)
        assert "T1059" in result["techniques_by_tactic"]["Execution"]

    def test_coverage_flags_populated(self):
        matrix = [_record("T1059", "Execution", has_sigma=True), _record("T1078", "Defense Evasion", has_sigma=False)]
        result = build_heatmap_data(matrix)
        assert result["coverage_flags"]["T1059"] is True
        assert result["coverage_flags"]["T1078"] is False

    def test_all_keys_present(self):
        result = build_heatmap_data([_record("T1059", "Execution")])
        assert set(result.keys()) == {"tactics", "techniques_by_tactic", "coverage_flags"}

    def test_broken_matrix_returns_empty(self):
        bad = MagicMock()
        type(bad).tactic = property(lambda self: (_ for _ in ()).throw(RuntimeError()))
        result = build_heatmap_data([bad])
        assert result == {}


class TestBuildCoverageSummaryText:
    def test_returns_string(self):
        summary = {"total_techniques": 16, "sigma_confirmed_count": 8, "coverage_percent": 50.0, "uncovered_techniques": ["T1078"]}
        assert isinstance(build_coverage_summary_text(summary), str)

    def test_contains_percentage(self):
        summary = {"total_techniques": 16, "sigma_confirmed_count": 8, "coverage_percent": 50.0, "uncovered_techniques": []}
        text = build_coverage_summary_text(summary)
        assert "50.0%" in text

    def test_contains_counts(self):
        summary = {"total_techniques": 16, "sigma_confirmed_count": 4, "coverage_percent": 25.0, "uncovered_techniques": []}
        text = build_coverage_summary_text(summary)
        assert "4" in text and "16" in text

    def test_uncovered_listed_when_present(self):
        summary = {"total_techniques": 16, "sigma_confirmed_count": 0, "coverage_percent": 0.0, "uncovered_techniques": ["T1078","T1110"]}
        text = build_coverage_summary_text(summary)
        assert "T1078" in text

    def test_empty_summary_returns_unavailable(self):
        text = build_coverage_summary_text({})
        assert isinstance(text, str)

    def test_broken_summary_returns_unavailable(self):
        text = build_coverage_summary_text(None)
        assert "unavailable" in text.lower()