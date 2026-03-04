"""
BaselineEngine — Phase 2
Computes and persists per-entity behavioral baselines using
scipy.stats.describe.  Requires ≥ 30 observations per D-004.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

import scipy.stats as stats

from loghunter.audit.logger import AuditLogger
from loghunter.engine.sqlite_layer import SQLiteLayer
from loghunter.exceptions import UnsupportedClassError
from loghunter.schema.metric_registry import MetricRegistry
from loghunter.schema.ocsf_event import OCSFEvent

_MIN_OBSERVATIONS = 30  # D-004


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class BaselineEngine:
    """
    Computes mean/stddev baselines for entity-metric pairs and persists
    them to the ``baselines`` SQLite table.
    """

    def __init__(
        self,
        sqlite_layer: SQLiteLayer,
        metric_registry: MetricRegistry,
        audit_logger: AuditLogger,
    ) -> None:
        """
        Raises TypeError if any argument is None.
        """
        if sqlite_layer is None:
            raise TypeError("sqlite_layer must not be None")
        if metric_registry is None:
            raise TypeError("metric_registry must not be None")
        if audit_logger is None:
            raise TypeError("audit_logger must not be None")

        self._db = sqlite_layer
        self._metrics = metric_registry
        self._audit = audit_logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_baseline(
        self,
        entity_type: str,
        entity_value: str,
        metric_name: str,
        class_uid: int,
        events: list[OCSFEvent],
    ) -> None:
        """
        Compute and persist a baseline for *entity_type* / *entity_value*
        using the named metric over *events*.

        Does nothing (silently) when ``len(events) < 30`` (D-004).

        Raises:
            TypeError:            If any argument is None or events is None.
            ValueError:           If entity_type/entity_value/metric_name
                                  are empty, or metric not registered.
            UnsupportedClassError: If class_uid not in SUPPORTED_CLASSES.
        """
        if entity_type is None:
            raise TypeError("entity_type must not be None")
        if entity_value is None:
            raise TypeError("entity_value must not be None")
        if metric_name is None:
            raise TypeError("metric_name must not be None")
        if class_uid is None:
            raise TypeError("class_uid must not be None")
        if events is None:
            raise TypeError("events must not be None")

        if not str(entity_type).strip():
            raise ValueError("entity_type must not be empty")
        if not str(entity_value).strip():
            raise ValueError("entity_value must not be empty")
        if not str(metric_name).strip():
            raise ValueError("metric_name must not be empty")

        # Validates class_uid — raises UnsupportedClassError if unknown
        metric_def = self._metrics.get_metric(metric_name, class_uid)
        if metric_def is None:
            raise ValueError(
                f"Metric '{metric_name}' not registered for class_uid={class_uid}"
            )

        if len(events) < _MIN_OBSERVATIONS:
            return  # D-004 — silent no-op

        # Compute per-event metric values
        values = self._collect_values(metric_name, class_uid, events)
        if len(values) < _MIN_OBSERVATIONS:
            return

        described = stats.describe(values)
        mean = float(described.mean)
        stddev = float(described.variance ** 0.5)  # describe gives variance

        window_start = min(e.get_time() for e in events).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        window_end = max(e.get_time() for e in events).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        computed_at = _now_utc()

        self._upsert_baseline(
            entity_type=entity_type,
            entity_value=entity_value,
            metric_name=metric_name,
            class_uid=class_uid,
            mean=mean,
            stddev=stddev,
            observation_count=len(values),
            window_start=window_start,
            window_end=window_end,
            computed_at=computed_at,
        )

    def get_baseline(
        self,
        entity_type: str,
        entity_value: str,
        metric_name: str,
        class_uid: int,
    ) -> Optional[dict]:
        """
        Return the stored baseline row as a dict, or None if not found.

        Raises:
            TypeError: If any argument is None.
        """
        if entity_type is None:
            raise TypeError("entity_type must not be None")
        if entity_value is None:
            raise TypeError("entity_value must not be None")
        if metric_name is None:
            raise TypeError("metric_name must not be None")
        if class_uid is None:
            raise TypeError("class_uid must not be None")

        rows = self._db.execute_read(
            """
            SELECT entity_type, entity_value, metric_name, class_uid,
                   mean, stddev, observation_count,
                   window_start, window_end, computed_at
              FROM baselines
             WHERE entity_type = ?
               AND entity_value = ?
               AND metric_name  = ?
               AND class_uid    = ?
             LIMIT 1
            """,
            (entity_type, entity_value, metric_name, class_uid),
        )
        if not rows:
            return None
        return dict(rows[0])

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_values(
        self, metric_name: str, class_uid: int, events: list[OCSFEvent]
    ) -> list[float]:
        """
        Compute the metric value for each individual event and return the
        list of floats.  Events where the metric returns None are skipped.
        """
        values: list[float] = []
        for event in events:
            val = self._metrics.compute_current_value(
                metric_name, class_uid, [event]
            )
            if val is not None:
                values.append(val)
        return values

    def _upsert_baseline(
        self,
        entity_type: str,
        entity_value: str,
        metric_name: str,
        class_uid: int,
        mean: float,
        stddev: float,
        observation_count: int,
        window_start: str,
        window_end: str,
        computed_at: str,
    ) -> None:
        """INSERT OR REPLACE into baselines (leverages UNIQUE constraint)."""
        self._db.execute_write(
            """
            INSERT INTO baselines (
                entity_type, entity_value, metric_name, class_uid,
                mean, stddev, observation_count,
                window_start, window_end, computed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entity_type, entity_value, metric_name, class_uid)
            DO UPDATE SET
                mean              = excluded.mean,
                stddev            = excluded.stddev,
                observation_count = excluded.observation_count,
                window_start      = excluded.window_start,
                window_end        = excluded.window_end,
                computed_at       = excluded.computed_at
            """,
            (
                entity_type,
                entity_value,
                metric_name,
                class_uid,
                mean,
                stddev,
                observation_count,
                window_start,
                window_end,
                computed_at,
            ),
        )