# loghunter/ui/components/attack_heatmap.py — Phase 3 #8
from __future__ import annotations
import streamlit as st

def build_heatmap_dataframe(heatmap_data: dict) -> "pd.DataFrame":
    """Convert heatmap_data to DataFrame. Rows=tactics, cols=technique IDs, values='sigma'|'rule'|'none'."""
    import pandas as pd
    if not heatmap_data:
        return pd.DataFrame()
    tactics = heatmap_data.get("tactics", [])
    techniques_by_tactic = heatmap_data.get("techniques_by_tactic", {})
    coverage_flags = heatmap_data.get("coverage_flags", {})
    all_techniques: list[str] = []
    seen: set[str] = set()
    for tactic in tactics:
        for tid in techniques_by_tactic.get(tactic, []):
            if tid not in seen:
                all_techniques.append(tid)
                seen.add(tid)
    if not all_techniques:
        return pd.DataFrame()
    rows = []
    for tactic in tactics:
        tactic_techs = set(techniques_by_tactic.get(tactic, []))
        row: dict = {"tactic": tactic}
        for tid in all_techniques:
            if tid in tactic_techs:
                row[tid] = "sigma" if coverage_flags.get(tid) else "rule"
            else:
                row[tid] = "none"
        rows.append(row)
    return pd.DataFrame(rows).set_index("tactic")

def render(heatmap_data: dict) -> None:
    """Render ATT&CK heatmap. Never raises."""
    try:
        import pandas as pd
        df = build_heatmap_dataframe(heatmap_data)
        if df.empty:
            st.info("No ATT&CK coverage data available.")
            return
        st.dataframe(df)
    except Exception:
        pass