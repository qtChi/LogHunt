# ==============================================================================
# loghunter/ingest/parsers/apache.py
#
# ApacheParser — parses Apache Combined Log Format access log lines.
#
# Per spec section 9: returns None for lines that cannot be parsed.
# Never raises.
#
# Apache Combined Log Format:
#   %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
#   Example:
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08"
# ==============================================================================

from __future__ import annotations

import re
from typing import Optional

from loghunter.ingest.parsers.base import LogParser

# Regex for Apache Combined Log Format
_APACHE_RE = re.compile(
    r'^(?P<client_ip>\S+)\s+'       # %h — client IP
    r'(?P<ident>\S+)\s+'            # %l — ident
    r'(?P<user>\S+)\s+'             # %u — user
    r'\[(?P<time>[^\]]+)\]\s+'      # %t — time
    r'"(?P<request>[^"]*)"\s+'      # "%r" — request line
    r'(?P<status>\d{3})\s+'         # %>s — status code
    r'(?P<bytes>\S+)'               # %b — bytes
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'  # combined
    r'\s*$'
)

_APACHE_NULL = "-"


class ApacheParser(LogParser):
    """
    Parser for Apache Combined Log Format access log lines.
    """

    @property
    def source_format(self) -> str:
        return "apache_access"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Parse a single Apache Combined Log Format line.

        Returns None for:
          - None input
          - Blank/whitespace input
          - Lines not matching the Apache combined log pattern

        Returns:
            Dict with keys: client_ip, ident, user, time, method, uri,
            protocol, status, bytes, referer, user_agent.
            Fields with value '-' are stored as None.
        """
        if raw_line is None:
            return None

        line = raw_line.strip()
        if not line:
            return None

        match = _APACHE_RE.match(line)
        if not match:
            return None

        groups = match.groupdict()

        # Split request line into method, uri, protocol
        request = groups.get("request", "") or ""
        request_parts = request.split(" ", 2)
        method = request_parts[0] if len(request_parts) > 0 else None
        uri = request_parts[1] if len(request_parts) > 1 else None
        protocol = request_parts[2] if len(request_parts) > 2 else None

        def _null(v: Optional[str]) -> Optional[str]:
            if v is None or v == _APACHE_NULL:
                return None
            return v

        return {
            "client_ip": _null(groups["client_ip"]),
            "ident": _null(groups["ident"]),
            "user": _null(groups["user"]),
            "time": groups["time"],
            "method": method or None,
            "uri": uri,
            "protocol": protocol,
            "status": groups["status"],
            "bytes": _null(groups["bytes"]),
            "referer": _null(groups.get("referer")),
            "user_agent": _null(groups.get("user_agent")),
        }