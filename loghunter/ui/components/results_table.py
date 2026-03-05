# loghunter/ui/components/results_table.py — Phase 3 #6
from __future__ import annotations
import streamlit as st

DEFAULT_COLUMNS: list[str] = [
    "time", "class_uid", "activity_id", "severity_id",
    "metadata.log_source", "actor.user.name",
    "src_endpoint.ip", "dst_endpoint.ip",
]

def select_display_columns(events: list[dict], preferred: list[str] = DEFAULT_COLUMNS) -> list[str]:
    """Return intersection of preferred and available columns. Falls back to first 8."""
    if not events:
        return preferred[:]
    available = list(events[0].keys())
    intersection = [c for c in preferred if c in available]
    if intersection:
        return intersection
    return available[:8]

def paginate_events(events: list[dict], page: int, page_size: int = 50) -> tuple[list[dict], int]:
    """Return (page_events, total_pages). Clamps out-of-range page. Raises ValueError if page_size < 1."""
    if page_size < 1:
        raise ValueError(f"page_size must be >= 1, got {page_size}")
    if not events:
        return [], 1
    total_pages = max(1, (len(events) + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    return events[start:start + page_size], total_pages

def render(events: list[dict], title: str = "Results", page_size: int = 50) -> None:
    """Render paginated results table. Never raises."""
    try:
        st.subheader(title)
        if not events:
            st.info("No results to display.")
            return
        st.caption(f"{len(events)} rows")
        columns = select_display_columns(events)
        if "page" not in st.session_state:
            st.session_state["page"] = 0
        page_events, total_pages = paginate_events(events, st.session_state["page"], page_size)
        display = [{c: row.get(c) for c in columns} for row in page_events]
        st.dataframe(display)
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("◀ Prev") and st.session_state["page"] > 0:
                st.session_state["page"] -= 1
        with col2:
            st.caption(f"Page {st.session_state['page'] + 1} of {total_pages}")
        with col3:
            if st.button("Next ▶") and st.session_state["page"] < total_pages - 1:
                st.session_state["page"] += 1
    except Exception:
        pass