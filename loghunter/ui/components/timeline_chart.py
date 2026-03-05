# loghunter/ui/components/timeline_chart.py — Phase 3 #7
from __future__ import annotations
from datetime import datetime, timedelta
import streamlit as st

def _floor_to_bucket(dt: datetime, bucket_minutes: int) -> datetime:
    total = dt.hour * 60 + dt.minute
    floored = (total // bucket_minutes) * bucket_minutes
    return dt.replace(hour=floored // 60, minute=floored % 60, second=0, microsecond=0)

def build_timeline_data(events: list[dict], bucket_minutes: int = 60) -> "pd.DataFrame":
    """Bucket events by time. Returns DataFrame(timestamp str, count int). Never raises on bad rows."""
    import pandas as pd
    if bucket_minutes < 1:
        raise ValueError(f"bucket_minutes must be >= 1, got {bucket_minutes}")
    if not events:
        return pd.DataFrame(columns=["timestamp", "count"])
    buckets: dict[datetime, int] = {}
    for event in events:
        t = event.get("time")
        if t is None:
            continue
        try:
            if not isinstance(t, datetime):
                t = datetime.fromisoformat(str(t))
            if t.tzinfo is not None:
                t = t.replace(tzinfo=None)
            bucketed = _floor_to_bucket(t, bucket_minutes)
            buckets[bucketed] = buckets.get(bucketed, 0) + 1
        except Exception:
            continue
    if not buckets:
        return pd.DataFrame(columns=["timestamp", "count"])
    sorted_buckets = sorted(buckets.items())
    return pd.DataFrame({
        "timestamp": [b.strftime("%Y-%m-%d %H:%M") for b, _ in sorted_buckets],
        "count": [c for _, c in sorted_buckets],
    })

def render(events: list[dict], title: str = "Event Timeline", bucket_minutes: int = 60) -> None:
    """Render event frequency bar chart. Never raises."""
    try:
        st.subheader(title)
        import pandas as pd
        df = build_timeline_data(events, bucket_minutes)
        if df.empty:
            st.info("No time data available for timeline.")
            return
        st.bar_chart(df.set_index("timestamp")["count"])
    except Exception:
        pass