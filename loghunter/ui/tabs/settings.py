# loghunter/ui/tabs/settings.py — Phase 3 #13 (Replay + Backtest tab)
from __future__ import annotations
import streamlit as st
from loghunter.ui.components import results_table

def create_and_ingest_session(session_name, events, replay_engine) -> dict:
    """Create replay session and ingest events. Never raises."""
    try:
        session_id = replay_engine.create_session(session_name)
        if events:
            event_count = replay_engine.ingest_to_session(events, session_id, "replay")
        else:
            event_count = 0
        return {"session_id": session_id, "event_count": event_count, "error": None}
    except Exception as exc:
        return {"session_id": None, "event_count": 0, "error": str(exc)}

def run_backtest(rule_id, session_id, replay_engine) -> dict:
    """Backtest rule against session. Never raises."""
    try:
        result = replay_engine.test_rule_against_session(rule_id, session_id)
        return {"result": result, "error": None}
    except Exception as exc:
        return {"result": None, "error": str(exc)}

def format_backtest_result(result) -> dict:
    """Convert BacktestResult to display dict. Never raises."""
    try:
        return {
            "rule_id": result.rule_id,
            "session_id": result.session_id,
            "match_count": result.match_count,
            "total_events": result.total_events,
            "match_rate": f"{result.match_count / result.total_events * 100:.1f}%" if result.total_events else "N/A",
            "executed_at": result.executed_at,
        }
    except Exception:
        return {}

def render(replay_engine, sigma_engine, builder) -> None:
    st.header("▶️ Replay — Backtest Rules")
    st.subheader("Create Session")
    session_name = st.text_input("Session name")
    if st.button("Create Session"):
        if not session_name:
            st.warning("Enter a session name.")
        else:
            r = create_and_ingest_session(session_name, [], replay_engine)
            if r["error"]:
                st.error(r["error"])
            else:
                st.success(f"Session created: {r['session_id']}")
                st.session_state["replay_session_id"] = r["session_id"]
    st.divider()
    st.subheader("Run Backtest")
    confirmed_rules = sigma_engine.list_rules(confirmed_only=True)
    if not confirmed_rules:
        st.info("No confirmed rules yet. Confirm a rule in the Rules tab first.")
        return
    rule_options = {r["rule_id"]: r["rule_id"] for r in confirmed_rules}
    rule_id = st.selectbox("Rule", list(rule_options.keys()))
    session_id = st.text_input("Session ID", value=st.session_state.get("replay_session_id", ""))
    if st.button("Run Backtest"):
        r = run_backtest(rule_id, session_id, replay_engine)
        if r["error"]:
            st.error(r["error"])
        elif r["result"]:
            d = format_backtest_result(r["result"])
            st.metric("Matches", d.get("match_count", 0))
            st.metric("Total Events", d.get("total_events", 0))
            results_table.render(r["result"].matched_events)