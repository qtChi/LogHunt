# ==============================================================================
# loghunter/schema/query_intent.py
#
# QueryIntent — typed model for structured query intent produced by
# IntentExtractor from a natural language analyst query.
#
# Per spec section 6.6 (Phase 3):
#   - FilterIntent holds a single filter condition (field, operator, value).
#   - QueryIntent holds the full structured representation of a NL query.
#   - Both validate eagerly in __post_init__ — invalid state never stored.
#   - Consumed by investigate.py to build a QueryBuilder call.
#
# Build Priority: Phase 3 — #1 in dependency order.
# ==============================================================================

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

VALID_OPERATORS: frozenset[str] = frozenset({
    "eq", "ne", "gt", "lt", "gte", "lte", "contains", "is_null", "not_null"
})


@dataclass
class FilterIntent:
    """
    A single filter condition derived from natural language.

    Attributes:
        field_path: OCSF dot-notation field e.g. "actor.user.name"
        operator:   One of VALID_OPERATORS
        value:      Filter value or None for is_null/not_null operators
    """
    field_path: str
    operator: str
    value: Optional[str | int | float] = None

    def __post_init__(self) -> None:
        """
        Raises TypeError  if field_path is None.
        Raises ValueError if field_path is empty/whitespace.
        Raises ValueError if operator not in VALID_OPERATORS.
        """
        if self.field_path is None:
            raise TypeError("field_path must not be None")
        if not str(self.field_path).strip():
            raise ValueError("field_path must not be empty or whitespace")
        if self.operator not in VALID_OPERATORS:
            raise ValueError(
                f"operator '{self.operator}' is not valid. "
                f"Must be one of: {sorted(VALID_OPERATORS)}"
            )


@dataclass
class QueryIntent:
    """
    Structured representation of an analyst's natural language query.
    Produced by IntentExtractor, consumed by investigate.py tab.

    Attributes:
        natural_language:  Original analyst query string preserved for display.
        class_uid:         OCSF class to query. None means analyst must select.
        filters:           List of FilterIntent conditions. Empty list = no filters.
        time_range_hours:  Lookback window in hours. None = no time filter.
        confidence:        LLM confidence score 0.0–1.0. None if unavailable.
    """
    natural_language: str
    class_uid: Optional[int] = None
    filters: list[FilterIntent] = field(default_factory=list)
    time_range_hours: Optional[int] = None
    confidence: Optional[float] = None

    def __post_init__(self) -> None:
        """
        Raises TypeError  if natural_language is None.
        Raises ValueError if natural_language is empty/whitespace.
        Raises ValueError if confidence not in 0.0–1.0 when provided.
        Raises ValueError if time_range_hours < 1 when provided.
        """
        if self.natural_language is None:
            raise TypeError("natural_language must not be None")
        if not str(self.natural_language).strip():
            raise ValueError("natural_language must not be empty or whitespace")
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be in range 0.0–1.0, got {self.confidence}"
            )
        if self.time_range_hours is not None and self.time_range_hours < 1:
            raise ValueError(
                f"time_range_hours must be >= 1, got {self.time_range_hours}"
            )

    def is_valid(self) -> bool:
        """
        Returns True if intent has enough info to execute a query.
        A valid intent requires class_uid to be set (not None).
        Never raises.
        """
        return self.class_uid is not None

    def to_builder_args(self) -> dict:
        """
        Convert to kwargs dict for QueryBuilder.execute():
        {
            "class_uid":   self.class_uid,
            "filters":     {f.field_path: f.value for f in self.filters},
            "time_range":  (now - timedelta(hours=time_range_hours), now)
                           or None if time_range_hours is None
        }

        Raises ValueError if is_valid() is False (class_uid is None).
        Never raises on empty filters list — returns empty dict for filters.
        """
        if not self.is_valid():
            raise ValueError(
                "QueryIntent is not valid (class_uid is None) — "
                "cannot build QueryBuilder args"
            )

        time_range = None
        if self.time_range_hours is not None:
            now = datetime.now(timezone.utc)
            time_range = (now - timedelta(hours=self.time_range_hours), now)

        return {
            "class_uid": self.class_uid,
            "filters": {f.field_path: f.value for f in self.filters},
            "time_range": time_range,
        }