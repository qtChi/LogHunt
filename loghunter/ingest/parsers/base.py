# ==============================================================================
# loghunter/ingest/parsers/base.py
#
# LogParser — abstract base class for all log format parsers.
#
# Per spec section 9:
#   - Subclasses implement parse(raw_line) → dict | None.
#   - Returns None for lines that cannot be parsed (malformed, header, comment).
#   - Never raises on a single bad line — bad lines return None.
#   - source_format property identifies the parser for audit logging.
#   - parse_batch processes a list of raw lines, collecting successes and
#     failures separately. Never raises.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class LogParser(ABC):
    """
    Abstract base class for all log format parsers.

    Subclasses implement parse() for a specific log format.
    parse_batch() is provided here and calls parse() per line.

    Per spec section 9.
    """

    @property
    @abstractmethod
    def source_format(self) -> str:
        """
        Identifier string for this parser's log format.

        Used in audit logging and normalizer registration.
        Examples: "zeek_conn", "evtx", "syslog", "apache_access".
        """

    @abstractmethod
    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Parse a single raw log line into a field dictionary.

        Args:
            raw_line: A single raw log line string.

        Returns:
            Dict of parsed fields, or None if the line cannot be parsed
            (malformed, blank, comment, header line).

        Never raises — all errors produce None.
        """

    def parse_batch(
        self, raw_lines: list[str]
    ) -> tuple[list[dict], list[str]]:
        """
        Parse a list of raw log lines.

        Calls parse() on each line. Lines that return None are collected
        as failures. Never raises.

        Args:
            raw_lines: List of raw log line strings.

        Returns:
            Tuple of (successes, failures) where:
              successes: List of successfully parsed field dicts.
              failures:  List of raw lines that could not be parsed.

        Raises:
            TypeError: If raw_lines is None.
        """
        if raw_lines is None:
            raise TypeError("raw_lines must not be None")

        successes: list[dict] = []
        failures: list[str] = []

        for line in raw_lines:
            try:
                result = self.parse(line)
            except Exception:
                result = None

            if result is not None:
                successes.append(result)
            else:
                failures.append(line)

        return successes, failures