# ==============================================================================
# loghunter/ingest/parsers/zeek.py
#
# ZeekParser — parses Zeek TSV log files (conn.log format).
#
# Per spec section 9: returns None for headers, comments, blank lines,
# wrong field count. Never raises.
#
# Zeek conn.log TSV format:
#   - Lines starting with '#' are comments/headers — skip silently.
#   - Tab-separated fields in a fixed column order defined by the #fields header.
#   - '-' represents a missing/null value in Zeek logs.
# ==============================================================================

from __future__ import annotations

from typing import Optional

from loghunter.ingest.parsers.base import LogParser

# Default Zeek conn.log column order when no #fields header is present.
_DEFAULT_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p",
    "id.resp_h", "id.resp_p", "proto", "service",
    "duration", "orig_bytes", "resp_bytes", "conn_state",
    "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
]

_ZEEK_NULL = "-"


class ZeekParser(LogParser):
    """
    Parser for Zeek TSV log files (conn.log format).

    Handles dynamic #fields header detection. Falls back to
    _DEFAULT_FIELDS if no header has been seen.
    """

    def __init__(self) -> None:
        self._fields: list[str] = list(_DEFAULT_FIELDS)

    @property
    def source_format(self) -> str:
        return "zeek_conn"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Parse a single Zeek conn.log TSV line.

        Returns None for:
          - None input
          - Blank lines
          - Comment/header lines (starting with '#')
          - Lines with wrong field count

        Returns:
            Dict of field name → value strings, or None.
        """
        if raw_line is None:
            return None

        line = raw_line.strip()

        if not line:
            return None

        if line.startswith("#"):
            # Update field list if this is the #fields header
            if line.startswith("#fields"):
                parts = line.split("\t")
                if len(parts) > 1:
                    self._fields = parts[1:]
            return None

        parts = line.split("\t")
        if len(parts) != len(self._fields):
            return None

        result = {}
        for field_name, value in zip(self._fields, parts):
            result[field_name] = None if value == _ZEEK_NULL else value

        return result