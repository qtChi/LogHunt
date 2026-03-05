# loghunter/ui/tabs/investigate.py — Phase 3 #10
from __future__ import annotations
from typing import Optional
import streamlit as st
from loghunter.ui.components import results_table, timeline_chart

def execute_nl_query(natural_language, extractor, builder) -> dict:
    """Extract intent then execute query. Never raises."""
    try:
        intent = extractor.extract(natural_language)
        if not intent.is_valid():
            return {"events": [], "intent": intent, "error": "Could not determine event class. Please refine your query.", "row_count": 0}
        args = intent.to_builder_args()
        events = builder.execute(args["class_uid"], args["filters"], args["time_range"])
        return {"events": events, "intent": intent, "error": None, "row_count": len(events)}
    except Exception as exc:
        return {"events": [], "intent": None, "error": str(exc), "row_count": 0}

def execute_manual_query(class_uid, filters, time_range_hours, builder) -> dict:
    """Execute manual query via QueryBuilder. Never raises."""
    try:
        from datetime import datetime, timedelta, timezone
        time_range = None
        if time_range_hours:
            now = datetime.now(timezone.utc)
            time_range = (now - timedelta(hours=time_range_hours), now)
        events = builder.execute(class_uid, filters or {}, time_range)
        return {"events": events, "intent": None, "error": None, "row_count": len(events)}
    except Exception as exc:
        return {"events": [], "intent": None, "error": str(exc), "row_count": 0}

def format_events_for_display(events) -> list[dict]:
    """Convert OCSFEvent list to flat dicts. Never raises."""
    result = []
    for event in (events or []):
        try:
            result.append(event.to_dict())
        except Exception:
            continue
    return result

def render(builder, extractor, ioc_matcher) -> None:
    st.header("🕵️ Investigate")
    mode = st.radio("Query mode", ["Natural Language", "Manual"])
    result = None
    if mode == "Natural Language":
        nl = st.text_area("Describe what you're looking for")
        if st.button("Run Query"):
            result = execute_nl_query(nl, extractor, builder)
            if result["intent"] and not result["intent"].is_available() if hasattr(result["intent"], "is_available") else False:
                st.warning("LLM unavailable — query may be incomplete.")
    else:
        CLASS_OPTIONS = {1001: "File System", 3001: "Network", 3002: "HTTP", 4001: "Process", 6003: "Authentication"}
        class_uid = st.selectbox("Event class", list(CLASS_OPTIONS.keys()), format_func=lambda x: CLASS_OPTIONS[x])
        hours = st.slider("Time window (hours)", 1, 168, 24)
        if st.button("Run Query"):
            result = execute_manual_query(class_uid, {}, hours, builder)
    if result:
        if result["error"]:
            st.error(result["error"])
        else:
            st.caption(f"{result['row_count']} events")
            rows = format_events_for_display(result["events"])
            if ioc_matcher and rows:
                for row in rows:
                    try:
                        from loghunter.schema.ocsf_event import OCSFEvent
                        pass
                    except Exception:
                        pass
            results_table.render(rows)
            timeline_chart.render(rows)