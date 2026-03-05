# loghunter/ui/tabs/coverage.py — Phase 3 #14
from __future__ import annotations
import streamlit as st
from loghunter.ui.components import attack_heatmap

def build_heatmap_data(matrix) -> dict:
    """Convert coverage matrix to heatmap component data. Never raises."""
    try:
        if not matrix:
            return {}
        tactics: list[str] = []
        techniques_by_tactic: dict[str, list[str]] = {}
        coverage_flags: dict[str, bool] = {}
        for record in matrix:
            if record.tactic not in tactics:
                tactics.append(record.tactic)
            if record.tactic not in techniques_by_tactic:
                techniques_by_tactic[record.tactic] = []
            techniques_by_tactic[record.tactic].append(record.technique_id)
            coverage_flags[record.technique_id] = record.has_sigma_rule
        return {"tactics": tactics, "techniques_by_tactic": techniques_by_tactic, "coverage_flags": coverage_flags}
    except Exception:
        return {}

def build_coverage_summary_text(summary: dict) -> str:
    """Build human-readable summary from get_coverage_summary() result. Never raises."""
    try:
        total = summary.get("total_techniques", 0)
        sigma = summary.get("sigma_confirmed_count", 0)
        pct = summary.get("coverage_percent", 0.0)
        uncovered = summary.get("uncovered_techniques", [])
        lines = [
            f"ATT&CK Coverage: {sigma}/{total} techniques ({pct:.1f}%)",
            f"Uncovered techniques: {len(uncovered)}",
        ]
        if uncovered:
            lines.append("Missing: " + ", ".join(uncovered[:10]))
        return "\n".join(lines)
    except Exception:
        return "Coverage data unavailable."

def render(coverage_engine) -> None:
    st.header("🛡️ Coverage — ATT&CK Matrix")
    try:
        summary = coverage_engine.get_coverage_summary()
        matrix = coverage_engine.get_coverage_matrix()
    except Exception as exc:
        st.error(str(exc))
        return
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Techniques", summary.get("total_techniques", 0))
    col2.metric("Sigma Covered", summary.get("sigma_confirmed_count", 0))
    col3.metric("Coverage %", f"{summary.get('coverage_percent', 0.0):.1f}%")
    st.text(build_coverage_summary_text(summary))
    st.subheader("ATT&CK Heatmap")
    heatmap_data = build_heatmap_data(matrix)
    attack_heatmap.render(heatmap_data)
    uncovered = summary.get("uncovered_techniques", [])
    if uncovered:
        st.subheader("Uncovered Techniques")
        import pandas as pd
        st.dataframe(pd.DataFrame({"technique_id": uncovered}))
    with st.expander("By Tactic"):
        for tactic, count in summary.get("by_tactic", {}).items():
            st.write(f"**{tactic}**: {count} techniques")