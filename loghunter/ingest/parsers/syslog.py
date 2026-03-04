# ==============================================================================
# loghunter/ingest/parsers/syslog.py
#
# SyslogParser — parses RFC 3164 syslog lines.
#
# Per spec section 9: returns None for lines that cannot be parsed.
# Never raises.
#
# RFC 3164 format:
#   <PRI>TIMESTAMP HOSTNAME PROCESS[PID]: MESSAGE
#   Example:
#   <34>Jan  5 06:00:00 mymachine su: 'su root' failed for user on /dev/pts/8
# ==============================================================================

from __future__ import annotations

import re
from typing import Optional

from loghunter.ingest.parsers.base import LogParser

# Regex for RFC 3164 syslog lines
# Groups: priority, month, day, time, hostname, process, pid, message
_SYSLOG_RE = re.compile(
    r"^(?:<(?P<priority>\d+)>)?"
    r"(?P<month>[A-Za-z]{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^:\[]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)


class SyslogParser(LogParser):
    """
    Parser for RFC 3164 syslog lines.
    """

    @property
    def source_format(self) -> str:
        return "syslog"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Parse a single RFC 3164 syslog line.

        Returns None for:
          - None input
          - Blank/whitespace input
          - Lines not matching the RFC 3164 pattern

        Returns:
            Dict with keys: priority, month, day, time, hostname,
            process, pid, message. pid is None if not present.
        """
        if raw_line is None:
            return None

        line = raw_line.strip()
        if not line:
            return None

        match = _SYSLOG_RE.match(line)
        if not match:
            return None

        groups = match.groupdict()
        return {
            "priority": groups["priority"],
            "month": groups["month"],
            "day": groups["day"],
            "time": groups["time"],
            "hostname": groups["hostname"],
            "process": groups["process"].strip(),
            "pid": groups["pid"],
            "message": groups["message"],
        }