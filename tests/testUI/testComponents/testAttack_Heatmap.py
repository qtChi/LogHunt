# tests/testUI/testAttackHeatmap.py — 100% branch coverage for attack_heatmap.py
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()

from loghunter.ui.components.attack_heatmap import build_heatmap_dataframe


def _data():
    return {
        "tactics": ["Execution", "Defense Evasion"],
        "techniques_by_tactic": {
            "Execution": ["T1059", "T1059.001"],
            "Defense Evasion": ["T1078"],
        },
        "coverage_flags": {"T1059": True, "T1059.001": False, "T1078": True},
    }


class TestBuildHeatmapDataframe:
    def test_empty_dict_returns_empty_df(self):
        df = build_heatmap_dataframe({})
        assert len(df) == 0

    def test_none_returns_empty_df(self):
        df = build_heatmap_dataframe(None)
        assert len(df) == 0

    def test_returns_dataframe(self):
        import pandas as pd
        df = build_heatmap_dataframe(_data())
        assert isinstance(df, pd.DataFrame)

    def test_rows_indexed_by_tactic(self):
        df = build_heatmap_dataframe(_data())
        assert "Execution" in df.index
        assert "Defense Evasion" in df.index

    def test_columns_are_technique_ids(self):
        df = build_heatmap_dataframe(_data())
        assert "T1059" in df.columns
        assert "T1059.001" in df.columns
        assert "T1078" in df.columns

    def test_sigma_value_when_covered(self):
        df = build_heatmap_dataframe(_data())
        assert df.loc["Execution", "T1059"] == "sigma"

    def test_rule_value_when_not_sigma(self):
        df = build_heatmap_dataframe(_data())
        assert df.loc["Execution", "T1059.001"] == "rule"

    def test_none_value_for_technique_not_in_tactic(self):
        df = build_heatmap_dataframe(_data())
        assert df.loc["Execution", "T1078"] == "none"

    def test_no_duplicate_columns(self):
        df = build_heatmap_dataframe(_data())
        assert len(df.columns) == len(set(df.columns))

    def test_empty_tactics_list_returns_empty(self):
        data = {"tactics": [], "techniques_by_tactic": {}, "coverage_flags": {}}
        df = build_heatmap_dataframe(data)
        assert len(df) == 0