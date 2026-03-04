"""
AnomalyDetector — Phase 2
Z-score anomaly detection against persisted baselines.
is_anomaly = abs(z_score) > 3.0
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from loghunter.engine.baseline import BaselineEngine
from loghunter.schema.metric_registry import MetricRegistry


@dataclass
class AnomalyResult:
    """Result of a single anomaly check."""

    entity_type: str
    entity_value: str
    metric_name: str
    current_value: float
    baseline_mean: float
    baseline_stddev: float
    z_score: float
    is_anomaly: bool  # abs(z_score) > 3.0
    threshold: float = field(default=3.0)


class AnomalyDetector:
    """
    Computes z-score deviation from persisted baselines and flags anomalies
    when ``abs(z_score) > 3.0``.
    """

    _ANOMALY_THRESHOLD = 3.0

    def __init__(
        self,
        baseline_engine: BaselineEngine,
        metric_registry: MetricRegistry,
    ) -> None:
        """
        Raises TypeError if any argument is None.
        """
        if baseline_engine is None:
            raise TypeError("baseline_engine must not be None")
        if metric_registry is None:
            raise TypeError("metric_registry must not be None")

        self._baseline = baseline_engine
        self._metrics = metric_registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(
        self,
        entity_type: str,
        entity_value: str,
        metric_name: str,
        class_uid: int,
        current_value: float,
    ) -> Optional[AnomalyResult]:
        """
        Compare *current_value* against the stored baseline for the
        given entity/metric combination.

        Returns:
            AnomalyResult  — if a baseline exists.
            None           — if no baseline has been computed yet
                             (no alert possible without a reference).

        Raises:
            TypeError: If any argument is None.
            ValueError: If current_value is not a real number (inf/nan
                        would produce meaningless z-scores).
        """
        if entity_type is None:
            raise TypeError("entity_type must not be None")
        if entity_value is None:
            raise TypeError("entity_value must not be None")
        if metric_name is None:
            raise TypeError("metric_name must not be None")
        if class_uid is None:
            raise TypeError("class_uid must not be None")
        if current_value is None:
            raise TypeError("current_value must not be None")

        import math

        if not isinstance(current_value, (int, float)) or isinstance(
            current_value, bool
        ):
            raise ValueError(
                f"current_value must be numeric, got {type(current_value)}"
            )
        if math.isnan(current_value) or math.isinf(current_value):
            raise ValueError(
                f"current_value must be finite, got {current_value}"
            )

        baseline = self._baseline.get_baseline(
            entity_type, entity_value, metric_name, class_uid
        )
        if baseline is None:
            return None

        mean = float(baseline["mean"])
        stddev = float(baseline["stddev"])

        # Guard against zero stddev (all observations identical)
        if stddev == 0.0:
            z_score = 0.0 if current_value == mean else float("inf")
            # Clamp inf to a large but finite value for comparisons
            if z_score == float("inf"):
                z_score = self._ANOMALY_THRESHOLD + 1.0
        else:
            z_score = (current_value - mean) / stddev

        is_anomaly = abs(z_score) > self._ANOMALY_THRESHOLD

        return AnomalyResult(
            entity_type=entity_type,
            entity_value=entity_value,
            metric_name=metric_name,
            current_value=float(current_value),
            baseline_mean=mean,
            baseline_stddev=stddev,
            z_score=z_score,
            is_anomaly=is_anomaly,
            threshold=self._ANOMALY_THRESHOLD,
        )