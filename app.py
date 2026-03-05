# app.py — Phase 3 #15 — Streamlit entry point
from __future__ import annotations
import streamlit as st
import ollama

from loghunter import config
from loghunter.engine.sqlite_layer import SQLiteLayer
from loghunter.engine.duckdb_layer import DuckDBLayer
from loghunter.engine.query_builder import QueryBuilder
from loghunter.engine.baseline import BaselineEngine
from loghunter.engine.anomaly import AnomalyDetector
from loghunter.engine.sigma_engine import SigmaEngine
from loghunter.engine.replay import ReplayEngine
from loghunter.engine.ioc_matcher import IOCMatcher
from loghunter.engine.mitre_mapper import MitreMapper
from loghunter.engine.coverage import CoverageEngine
from loghunter.audit.logger import AuditLogger
from loghunter.audit.metrics import AuditMetrics
from loghunter.ingest.normalizer import OCSFNormalizer
from loghunter.ingest.writer import ParquetWriter
from loghunter.llm.intent_extractor import IntentExtractor
from loghunter.llm.anomaly_explainer import AnomalyExplainer
from loghunter.llm.sigma_draft_generator import SigmaDraftGenerator
from loghunter.schema.ocsf_field_registry import OCSFFieldRegistry
from loghunter.schema.metric_registry import MetricRegistry

from loghunter.ui.tabs import hunt, investigate, metrics, rules, settings, coverage


@st.cache_resource
def _init_deps() -> dict:
    """Initialise all shared dependencies once per Streamlit session."""
    try:
        registry = OCSFFieldRegistry("config/ocsf_schema.json")
        metric_registry = MetricRegistry("config/metrics.json")
        sqlite_layer = SQLiteLayer(config.METADATA_DB_PATH)
        audit_logger = AuditLogger(sqlite_layer)
        audit_metrics = AuditMetrics(audit_logger)
        duckdb_layer = DuckDBLayer(config.PARQUET_BASE_PATH)
        mitre_mapper = MitreMapper()
        normalizer = OCSFNormalizer(registry, mitre_mapper, audit_logger)
        writer = ParquetWriter(config.PARQUET_BASE_PATH, audit_logger)
        query_builder = QueryBuilder(duckdb_layer, registry, audit_logger)
        baseline_engine = BaselineEngine(sqlite_layer, metric_registry, audit_logger)
        anomaly_detector = AnomalyDetector(baseline_engine, metric_registry)
        sigma_engine = SigmaEngine(sqlite_layer, audit_logger, duckdb_layer)
        replay_engine = ReplayEngine(writer, sigma_engine, duckdb_layer)
        ioc_matcher = IOCMatcher("iocs/")
        coverage_engine = CoverageEngine(mitre_mapper, sigma_engine)
        ollama_client = ollama.Client(host=config.OLLAMA_HOST)
        intent_extractor = IntentExtractor(ollama_client)
        anomaly_explainer = AnomalyExplainer(ollama_client)
        sigma_draft_gen = SigmaDraftGenerator(ollama_client)
        return {
            "registry": registry,
            "metric_registry": metric_registry,
            "sqlite_layer": sqlite_layer,
            "audit_logger": audit_logger,
            "audit_metrics": audit_metrics,
            "duckdb_layer": duckdb_layer,
            "mitre_mapper": mitre_mapper,
            "normalizer": normalizer,
            "writer": writer,
            "query_builder": query_builder,
            "baseline_engine": baseline_engine,
            "anomaly_detector": anomaly_detector,
            "sigma_engine": sigma_engine,
            "replay_engine": replay_engine,
            "ioc_matcher": ioc_matcher,
            "coverage_engine": coverage_engine,
            "intent_extractor": intent_extractor,
            "anomaly_explainer": anomaly_explainer,
            "sigma_draft_gen": sigma_draft_gen,
        }
    except Exception as exc:
        st.error(f"Initialisation failed: {exc}")
        return {}


def main() -> None:
    st.set_page_config(page_title="LogHunt", page_icon="🔍", layout="wide")
    st.title("LogHunt — Detection Engineering Workbench")
    deps = _init_deps()
    if not deps:
        st.stop()
    tab_hunt, tab_inv, tab_met, tab_rules, tab_replay, tab_cov = st.tabs([
        "🔍 Hunt", "🕵️ Investigate", "📊 Metrics", "📜 Rules", "▶️ Replay", "🛡️ Coverage"
    ])
    with tab_hunt:
        hunt.render(deps["normalizer"], deps["writer"])
    with tab_inv:
        investigate.render(deps["query_builder"], deps["intent_extractor"], deps["ioc_matcher"])
    with tab_met:
        metrics.render(deps["query_builder"], deps["baseline_engine"], deps["anomaly_detector"], deps["metric_registry"], deps["anomaly_explainer"])
    with tab_rules:
        rules.render(deps["sigma_engine"], deps["sigma_draft_gen"], deps["query_builder"])
    with tab_replay:
        settings.render(deps["replay_engine"], deps["sigma_engine"], deps["query_builder"])
    with tab_cov:
        coverage.render(deps["coverage_engine"])


if __name__ == "__main__":
    main()