# ==============================================================================
# loghunter/schema/metric_registry.py
#
# MetricRegistry — central authority for all baseline metric definitions.
#
# Per spec section 7:
#   - Loaded once at startup from config/metrics.json.
#   - Defines which metrics exist, which event classes they apply to,
#     how current values are computed, and which entity fields they group by.
#   - BaselineEngine and AnomalyDetector depend on it.
#   - Immutable after construction.
#
# Computation dispatch uses a private dict of pure handler functions so
# each aggregation type is independently testable and adding a new type
# is one dict entry — no modification of existing logic required.
#
# Build Priority: Phase 1 — must exist before BaselineEngine.
# ==============================================================================

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from loghunter.exceptions import UnsupportedClassError
from loghunter.schema.ocsf_field_registry import SUPPORTED_CLASSES

if TYPE_CHECKING:
    from loghunter.schema.ocsf_event import OCSFEvent

# Supported aggregation computation types
SUPPORTED_COMPUTATIONS: frozenset[str] = frozenset({
    "count",
    "distinct_field_count",
    "sum_field",
    "rate_per_hour",
})


@dataclass(frozen=True)
class MetricDefinition:
    """
    Immutable descriptor for a single baseline metric.

    Per spec section 7: read-only data class — no setters.

    Attributes:
        metric_name:   Unique name e.g. "auth_count_per_hour".
        class_uid:     The OCSF event class this metric applies to.
        entity_type:   The entity this metric is grouped by e.g. "user", "ip".
        entity_field:  OCSF field path of the entity value.
        computation:   Aggregation type — one of SUPPORTED_COMPUTATIONS.
        target_field:  Field used for distinct_field_count and sum_field.
                       None for count and rate_per_hour.
        description:   Human-readable description.
    """
    metric_name: str
    class_uid: int
    entity_type: str
    entity_field: str
    computation: str
    target_field: Optional[str]
    description: str


# ==============================================================================
# Computation handlers — pure functions, independently testable
# ==============================================================================

def _compute_count(events: list[OCSFEvent], target_field: Optional[str]) -> float:
    """Return total event count."""
    return float(len(events))


def _compute_distinct_field_count(
    events: list[OCSFEvent], target_field: Optional[str]
) -> Optional[float]:
    """Return count of distinct non-None values for target_field."""
    if not target_field:
        return None
    seen = set()
    for event in events:
        val = event._fields.get(target_field)
        if val is not None:
            seen.add(val)
    return float(len(seen))


def _compute_sum_field(
    events: list[OCSFEvent], target_field: Optional[str]
) -> Optional[float]:
    """Return sum of numeric target_field values across events."""
    if not target_field:
        return None
    total = 0.0
    for event in events:
        val = event._fields.get(target_field)
        if val is not None:
            try:
                total += float(val)
            except (TypeError, ValueError):
                pass
    return total


def _compute_rate_per_hour(
    events: list[OCSFEvent], target_field: Optional[str]
) -> Optional[float]:
    """
    Return event rate per hour.

    Derived from the time span between the earliest and latest event.
    Returns None if fewer than two events (cannot compute a time span).
    """
    if len(events) < 2:
        return None
    times = []
    for event in events:
        t = event._fields.get("time")
        if t is not None:
            times.append(t)
    if len(times) < 2:
        return None
    span_seconds = (max(times) - min(times)).total_seconds()
    if span_seconds <= 0:
        return None
    span_hours = span_seconds / 3600.0
    return float(len(events)) / span_hours


_COMPUTATION_HANDLERS = {
    "count": _compute_count,
    "distinct_field_count": _compute_distinct_field_count,
    "sum_field": _compute_sum_field,
    "rate_per_hour": _compute_rate_per_hour,
}


# ==============================================================================
# MetricRegistry
# ==============================================================================

class MetricRegistry:
    """
    Central authority for all baseline metric definitions.

    Loaded once from config/metrics.json. Immutable after construction.
    BaselineEngine and AnomalyDetector depend on this class.

    Per spec section 7.
    """

    def __init__(self, metrics_path: str) -> None:
        """
        Load metric definitions from a JSON file at metrics_path.

        Args:
            metrics_path: Path to metrics.json.

        Raises:
            TypeError:         If metrics_path is None.
            ValueError:        If metrics_path is empty or whitespace.
            FileNotFoundError: If path does not exist.
            ValueError:        If JSON is malformed or any metric definition
                               is missing required fields.
        """
        if metrics_path is None:
            raise TypeError("metrics_path must not be None")
        if not str(metrics_path).strip():
            raise ValueError("metrics_path must not be empty or whitespace")

        path = Path(metrics_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Metrics config file not found: {metrics_path}"
            )

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Metrics config file is not valid JSON: {exc}"
            ) from exc

        if "metrics" not in raw or not isinstance(raw["metrics"], list):
            raise ValueError(
                "Metrics JSON must contain a top-level 'metrics' list."
            )

        # _by_name_class: (metric_name, class_uid) -> MetricDefinition
        # _by_class: class_uid -> list[MetricDefinition]
        self._by_name_class: dict[tuple[str, int], MetricDefinition] = {}
        self._by_class: dict[int, list[MetricDefinition]] = {
            uid: [] for uid in SUPPORTED_CLASSES
        }

        for raw_metric in raw["metrics"]:
            md = self._parse_metric(raw_metric)
            key = (md.metric_name, md.class_uid)
            if key in self._by_name_class:
                raise ValueError(
                    f"Duplicate metric definition: name='{md.metric_name}' "
                    f"class_uid={md.class_uid}"
                )
            self._by_name_class[key] = md
            if md.class_uid in self._by_class:
                self._by_class[md.class_uid].append(md)

    # --------------------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------------------

    def _parse_metric(self, raw: dict) -> MetricDefinition:
        """Parse and validate a single metric dict from JSON."""
        required_keys = {
            "metric_name", "class_uid", "entity_type",
            "entity_field", "computation",
        }
        missing = required_keys - raw.keys()
        if missing:
            raise ValueError(
                f"Metric definition missing required keys {missing}: {raw}"
            )

        computation = str(raw["computation"])
        if computation not in SUPPORTED_COMPUTATIONS:
            raise ValueError(
                f"Unsupported computation type '{computation}'. "
                f"Must be one of {sorted(SUPPORTED_COMPUTATIONS)}."
            )

        return MetricDefinition(
            metric_name=str(raw["metric_name"]),
            class_uid=int(raw["class_uid"]),
            entity_type=str(raw["entity_type"]),
            entity_field=str(raw["entity_field"]),
            computation=computation,
            target_field=raw.get("target_field") or None,
            description=str(raw.get("description", "")),
        )

    # --------------------------------------------------------------------------
    # Public API — per spec section 7
    # --------------------------------------------------------------------------

    def get_metric(
        self, metric_name: str, class_uid: int
    ) -> Optional[MetricDefinition]:
        """
        Return the MetricDefinition for a given metric name and class UID.

        Returns None if no such metric is registered. Never raises.

        Args:
            metric_name: Metric name string.
            class_uid:   Event class identifier.

        Returns:
            MetricDefinition or None.
        """
        return self._by_name_class.get((metric_name, class_uid))

    def get_metrics_for_class(self, class_uid: int) -> list[MetricDefinition]:
        """
        Return all metric definitions registered for a given event class.

        Returns empty list if no metrics registered for that class.

        Args:
            class_uid: One of {1001, 3001, 3002, 4001, 6003}.

        Returns:
            List of MetricDefinition objects.

        Raises:
            UnsupportedClassError: If class_uid is not a supported class.
        """
        if class_uid not in SUPPORTED_CLASSES:
            raise UnsupportedClassError(
                f"class_uid {class_uid} is not supported. "
                f"Supported: {sorted(SUPPORTED_CLASSES)}"
            )
        return list(self._by_class[class_uid])

    def compute_current_value(
        self,
        metric_name: str,
        class_uid: int,
        events: list[OCSFEvent],
    ) -> Optional[float]:
        """
        Compute the current value of a metric from a list of events.

        Computation logic is defined by MetricDefinition.computation.

        Args:
            metric_name: Registered metric name.
            class_uid:   Event class identifier.
            events:      List of OCSFEvent objects to compute over.

        Returns:
            Float value or None if events is empty or metric cannot be
            computed from the provided events.

        Raises:
            TypeError:  If events is None.
            ValueError: If metric_name is not registered for class_uid.
        """
        if events is None:
            raise TypeError("events must not be None")

        md = self._by_name_class.get((metric_name, class_uid))
        if md is None:
            raise ValueError(
                f"Metric '{metric_name}' is not registered for "
                f"class_uid {class_uid}."
            )

        if len(events) == 0:
            return None

        handler = _COMPUTATION_HANDLERS[md.computation]
        return handler(events, md.target_field)