"""
IOCMatcher — Phase 2
Loads IOC flat files at construction and matches them against
OCSF event fields: src_endpoint.ip, dst_endpoint.ip, file.path,
actor.user.name.
Row cap: 100,000 per file (D-008).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from loghunter.schema.ocsf_event import OCSFEvent

_ROW_CAP = 100_000  # D-008

# OCSF field paths checked during match_event
_MATCH_FIELDS = (
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "file.path",
    "actor.user.name",
)


class IOCMatcher:
    """
    In-memory IOC store loaded from flat files (one IOC value per line).
    """

    def __init__(self, ioc_dir: str) -> None:
        """
        Args:
            ioc_dir: Directory containing IOC flat files.  The directory
                     is created if it does not exist.

        Raises:
            TypeError:  If ioc_dir is None.
            ValueError: If ioc_dir is empty/whitespace.
        """
        if ioc_dir is None:
            raise TypeError("ioc_dir must not be None")
        if not str(ioc_dir).strip():
            raise ValueError("ioc_dir must not be empty")

        self._ioc_dir = Path(ioc_dir)
        self._ioc_dir.mkdir(parents=True, exist_ok=True)

        # Flat set of all loaded IOC values (lower-cased for comparison)
        self._iocs: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_iocs(self, filename: str) -> int:
        """
        Load IOC values from *filename* inside ``ioc_dir``.
        Blank lines and lines beginning with ``#`` are skipped.
        Silently truncates at 100,000 rows (D-008).

        Returns:
            Count of IOC values loaded from this file (before dedup
            against already-loaded IOCs).

        Raises:
            TypeError:     If filename is None.
            ValueError:    If filename is empty/whitespace.
            FileNotFoundError: If the file does not exist in ioc_dir.
        """
        if filename is None:
            raise TypeError("filename must not be None")
        if not str(filename).strip():
            raise ValueError("filename must not be empty")

        filepath = self._ioc_dir / filename
        if not filepath.exists():
            raise FileNotFoundError(
                f"IOC file not found: {filepath}"
            )

        loaded = 0
        with filepath.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if loaded >= _ROW_CAP:
                    break  # D-008 — silently truncate
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                self._iocs.add(value.lower())
                loaded += 1

        return loaded

    def match_event(self, event: OCSFEvent) -> list[str]:
        """
        Return a list of IOC values found in any of the watched event
        fields (src_endpoint.ip, dst_endpoint.ip, file.path,
        actor.user.name).

        Returns an empty list when no IOCs match or when no IOCs are
        loaded.

        Raises:
            TypeError: If event is None.
        """
        if event is None:
            raise TypeError("event must not be None")

        if not self._iocs:
            return []

        matched: list[str] = []
        for field_path in _MATCH_FIELDS:
            try:
                value = event.get_field(field_path)
            except (ValueError, TypeError):
                continue  # field not registered for this class — skip

            if value is None:
                continue

            normalised = str(value).lower()
            if normalised in self._iocs:
                matched.append(str(value))

        return matched

    def get_ioc_count(self) -> int:
        """Return the total number of unique IOC values currently loaded."""
        return len(self._iocs)