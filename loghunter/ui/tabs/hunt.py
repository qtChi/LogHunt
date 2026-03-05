# loghunter/ui/tabs/hunt.py — Phase 3 #9
from __future__ import annotations
import streamlit as st
from loghunter.ingest.parsers.zeek import ZeekParser
from loghunter.ingest.parsers.evtx import EVTXParser
from loghunter.ingest.parsers.syslog import SyslogParser
from loghunter.ingest.parsers.apache import ApacheParser

FORMAT_OPTIONS: dict[str, tuple[str, int, type]] = {
    "Zeek conn.log (Network Activity)":        ("zeek",   3001, ZeekParser),
    "Apache Access Log (HTTP Activity)":        ("apache", 3002, ApacheParser),
    "Windows EVTX — Sysmon (Process Activity)": ("evtx",  4001, EVTXParser),
    "Windows EVTX — Security (Authentication)": ("evtx",  6003, EVTXParser),
    "Syslog (File System Activity)":            ("syslog", 1001, SyslogParser),
}

CLASS_UID_NAMES: dict[int, str] = {
    1001: "File System Activity",
    3001: "Network Activity",
    3002: "HTTP Activity",
    4001: "Process Activity",
    6003: "Authentication Activity",
}

def decode_uploaded_file(raw_bytes: bytes) -> list[str]:
    """Decode bytes to non-empty lines. UTF-8 first, latin-1 fallback."""
    if raw_bytes is None:
        raise TypeError("raw_bytes must not be None")
    if not raw_bytes:
        raise ValueError("raw_bytes must not be empty")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = raw_bytes.decode("latin-1")
    return [line for line in text.splitlines() if line.strip()]

def run_ingest(lines, source_format, class_uid, parser_class, normalizer, writer, file_name="unknown") -> dict:
    """Parse, normalise, write. Returns result dict. Never raises."""
    try:
        parser = parser_class()
        raw_dicts = parser.parse_lines(lines)
        parsed_count = len(raw_dicts)
        failed_parse = len(lines) - parsed_count

        events, failed_norm = normalizer.normalize_batch(raw_dicts, source_format, class_uid)
        normalised_count = len(events)
        failed_normalise = len(failed_norm)

        written_count = writer.write_batch(events, source_format, file_name)
        return {
            "parsed_count": parsed_count,
            "failed_parse": failed_parse,
            "normalised_count": normalised_count,
            "failed_normalise": failed_normalise,
            "written_count": written_count,
            "error": None,
        }
    except Exception as exc:
        return {
            "parsed_count": 0, "failed_parse": 0,
            "normalised_count": 0, "failed_normalise": 0,
            "written_count": 0, "error": str(exc),
        }

def build_summary_message(result: dict) -> str:
    """Human-readable summary with ✅ or ❌ prefix."""
    if result.get("error"):
        return f"❌ Ingest failed: {result['error']}"
    return (
        f"✅ Ingested {result['written_count']} events "
        f"({result['failed_parse']} parse failures, "
        f"{result['failed_normalise']} normalise failures)"
    )

def render(normalizer, writer) -> None:
    st.header("🔍 Hunt — Log Ingest")
    label = st.selectbox("Log format", list(FORMAT_OPTIONS.keys()))
    source_format, class_uid, parser_class = FORMAT_OPTIONS[label]
    uploaded = st.file_uploader("Upload log file", type=None)
    if st.button("Run Ingest"):
        if uploaded is None:
            st.warning("Please upload a file first.")
            return
        try:
            lines = decode_uploaded_file(uploaded.read())
            result = run_ingest(lines, source_format, class_uid, parser_class, normalizer, writer, uploaded.name)
            msg = build_summary_message(result)
            if result.get("error"):
                st.error(msg)
            else:
                st.success(msg)
        except Exception as exc:
            st.error(f"❌ {exc}")