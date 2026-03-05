# loghunter/ui/tabs/metrics.py — Phase 3 #11
from __future__ import annotations
from typing import Optional
import streamlit as st

def get_available_entities(events, entity_field: str) -> list[str]:
    """Extract unique non-None entity values for a given field. Never raises."""
    entities: set[str] = set()
    for event in (events or []):
        try:
            val = event.get_field(entity_field)
            if val is not None:
                entities.add(str(val))
        except Exception:
            continue
    return sorted(entities)

def compute_and_detect(entity_type, entity_value, metric_name, class_uid, events,
                        baseline_engine, anomaly_detector, metric_registry) -> dict:
    """Compute baseline then run anomaly detection. Never raises."""
    try:
        current_value = float(len(events or []))
        baseline_engine.compute_baseline(entity_type, entity_value, metric_name, class_uid, events or [])
        baseline = baseline_engine.get_baseline(entity_type, entity_value, metric_name, class_uid)
        anomaly_result = anomaly_detector.detect(entity_type, entity_value, metric_name, class_uid, current_value)
        return {"baseline": baseline, "anomaly_result": anomaly_result, "current_value": current_value, "error": None}
    except Exception as exc:
        return {"baseline": None, "anomaly_result": None, "current_value": None, "error": str(exc)}

def format_anomaly_for_display(result) -> dict:
    """Convert AnomalyResult to display dict. Never raises."""
    try:
        return {
            "entity": f"{result.entity_type}={result.entity_value}",
            "metric": result.metric_name,
            "current_value": result.current_value,
            "baseline_mean": result.baseline_mean,
            "z_score": result.z_score,
            "is_anomaly": result.is_anomaly,
        }
    except Exception:
        return {}

def render(builder, baseline_engine, anomaly_detector, metric_registry, explainer) -> None:
    st.header("📊 Metrics — Baseline & Anomaly")
    CLASS_OPTIONS = {1001: "File System", 3001: "Network", 3002: "HTTP", 4001: "Process", 6003: "Authentication"}
    class_uid = st.selectbox("Event class", list(CLASS_OPTIONS.keys()), format_func=lambda x: CLASS_OPTIONS[x])
    entity_type = st.selectbox("Entity type", ["user", "ip", "host", "process"])
    entity_value = st.text_input("Entity value")
    try:
        metric_names = metric_registry.get_metric_names()
    except Exception:
        metric_names = []
    metric_name = st.selectbox("Metric", metric_names) if metric_names else st.text_input("Metric name")
    hours = st.slider("Time window (hours)", 1, 168, 24)
    if st.button("Compute"):
        if not entity_value:
            st.warning("Enter an entity value.")
            return
        try:
            from datetime import datetime, timedelta, timezone
            now = datetime.now(timezone.utc)
            events = builder.execute(class_uid, {}, (now - timedelta(hours=hours), now))
        except Exception as exc:
            st.error(str(exc))
            return
        result = compute_and_detect(entity_type, entity_value, metric_name, class_uid, events, baseline_engine, anomaly_detector, metric_registry)
        if result["error"]:
            st.error(result["error"])
            return
        if result["anomaly_result"]:
            d = format_anomaly_for_display(result["anomaly_result"])
            st.warning(f"🚨 Anomaly detected — z-score: {d.get('z_score', 'N/A'):.2f}")
            st.json(d)
            explanation = explainer.explain(result["anomaly_result"], {})
            st.text_area("LLM Explanation", explanation, height=100)
        else:
            st.success(f"✅ No anomaly. Current value: {result['current_value']}")