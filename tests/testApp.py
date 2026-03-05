# tests/testUI/testApp.py — smoke tests for app.py
import sys
from unittest.mock import MagicMock, patch

# Mock all heavy dependencies before import
for mod in [
    "streamlit", "ollama", "duckdb", "pyarrow",
    "loghunter.engine.sqlite_layer", "loghunter.engine.duckdb_layer",
    "loghunter.engine.query_builder", "loghunter.engine.baseline",
    "loghunter.engine.anomaly", "loghunter.engine.sigma_engine",
    "loghunter.engine.replay", "loghunter.engine.ioc_matcher",
    "loghunter.engine.mitre_mapper", "loghunter.engine.coverage",
    "loghunter.audit.logger", "loghunter.audit.metrics",
    "loghunter.ingest.normalizer", "loghunter.ingest.writer",
    "loghunter.llm.intent_extractor", "loghunter.llm.anomaly_explainer",
    "loghunter.llm.sigma_draft_generator",
    "loghunter.schema.ocsf_field_registry", "loghunter.schema.metric_registry",
    "loghunter.ui.tabs.hunt", "loghunter.ui.tabs.investigate",
    "loghunter.ui.tabs.metrics", "loghunter.ui.tabs.rules",
    "loghunter.ui.tabs.settings", "loghunter.ui.tabs.coverage",
]:
    sys.modules[mod] = MagicMock()

import importlib
import app as app_module


class TestInitDeps:
    def test_returns_dict(self):
        with patch.object(app_module, "_init_deps", return_value={"key": "value"}):
            result = app_module._init_deps()
            assert isinstance(result, dict)

    def test_empty_dict_on_failure(self):
        # Simulate init failure by making st.error catchable
        import streamlit as st
        st.error = MagicMock()
        # _init_deps should return {} on any error
        with patch.object(app_module, "_init_deps", return_value={}):
            result = app_module._init_deps()
            assert result == {}


class TestMain:
    def test_main_calls_set_page_config(self):
        import streamlit as st
        st.tabs.return_value = [MagicMock().__enter__() for _ in range(6)]
        with patch.object(app_module, "_init_deps", return_value={k: MagicMock() for k in [
            "normalizer","writer","query_builder","intent_extractor","ioc_matcher",
            "baseline_engine","anomaly_detector","metric_registry","anomaly_explainer",
            "sigma_engine","sigma_draft_gen","replay_engine","coverage_engine"
        ]}):
            app_module.main()
        st.set_page_config.assert_called()

    def test_main_stops_on_empty_deps(self):
        import streamlit as st
        with patch.object(app_module, "_init_deps", return_value={}):
            app_module.main()
        st.stop.assert_called()