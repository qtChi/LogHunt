"""
AnomalyExplainer — Phase 2 LLM Layer
Wraps Ollama to generate human-readable explanations for anomalies.
If Ollama is unavailable at construction or call time, returns a
placeholder string and never raises (D-003).
"""
from __future__ import annotations

import logging
from typing import Any

from loghunter.config import LLM_MODEL
from loghunter.engine.anomaly import AnomalyResult

logger = logging.getLogger(__name__)

_PLACEHOLDER = (
    "[LLM unavailable] Anomaly detected: {metric_name} for "
    "{entity_type}={entity_value} deviated {z_score:.2f} standard "
    "deviations from the baseline mean of {baseline_mean:.4f} "
    "(current value: {current_value:.4f})."
)


class AnomalyExplainer:
    """
    Generates natural-language explanations of AnomalyResult objects
    using a local Ollama model.

    Degrades gracefully: if Ollama is down, a structured placeholder
    string is returned so analyst workflow is never blocked (D-003).
    """

    def __init__(
        self,
        ollama_client: Any,
        model: str = LLM_MODEL,
    ) -> None:
        """
        Args:
            ollama_client: An ``ollama`` client instance (or compatible
                           duck-type).  Availability is probed at init;
                           failures set _available=False.
            model:         Ollama model tag.  Defaults to LLM_MODEL from
                           config.

        Raises:
            TypeError: If ollama_client is None.
        """
        if ollama_client is None:
            raise TypeError("ollama_client must not be None")

        self._client = ollama_client
        self._model = model
        self._available = self._probe_availability()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def explain(
        self,
        anomaly_result: AnomalyResult,
        entity_context: dict,
    ) -> str:
        """
        Return a human-readable explanation of why *anomaly_result* is
        notable, enriched with *entity_context*.

        Never raises regardless of Ollama state (D-003).
        Returns a placeholder when Ollama is unavailable.

        Args:
            anomaly_result: The anomaly to explain.
            entity_context: Additional context dict (recent events,
                            user info, etc.) included in the prompt.
        """
        try:
            if anomaly_result is None:
                return self._placeholder(None)
            if not self._available:
                return self._placeholder(anomaly_result)

            prompt = self._build_prompt(anomaly_result, entity_context or {})
            response = self._client.chat(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
            )
            text = (
                response.get("message", {}).get("content", "")
                if isinstance(response, dict)
                else str(response)
            )
            return text.strip() or self._placeholder(anomaly_result)
        except Exception as exc:
            logger.warning("AnomalyExplainer: Ollama call failed — %s", exc)
            self._available = False
            return self._placeholder(anomaly_result)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _probe_availability(self) -> bool:
        """
        Check whether the Ollama endpoint is reachable.
        Returns True on success, False (and logs warning) on any error.
        """
        try:
            self._client.list()
            return True
        except Exception as exc:
            logger.warning(
                "AnomalyExplainer: Ollama unavailable at init — %s", exc
            )
            return False

    @staticmethod
    def _build_prompt(result: AnomalyResult, context: dict) -> str:
        context_str = (
            "\n".join(f"  {k}: {v}" for k, v in context.items())
            if context
            else "  (no additional context)"
        )
        return (
            f"You are a SOC analyst assistant.\n\n"
            f"An anomaly was detected:\n"
            f"  Entity:          {result.entity_type}={result.entity_value}\n"
            f"  Metric:          {result.metric_name}\n"
            f"  Current value:   {result.current_value:.4f}\n"
            f"  Baseline mean:   {result.baseline_mean:.4f}\n"
            f"  Baseline stddev: {result.baseline_stddev:.4f}\n"
            f"  Z-score:         {result.z_score:.2f}\n\n"
            f"Entity context:\n{context_str}\n\n"
            f"In 2-3 sentences, explain why this anomaly is notable and "
            f"what the analyst should investigate."
        )

    @staticmethod
    def _placeholder(result: "AnomalyResult | None") -> str:
        if result is None:
            return "[LLM unavailable] No anomaly result provided."
        return _PLACEHOLDER.format(
            metric_name=result.metric_name,
            entity_type=result.entity_type,
            entity_value=result.entity_value,
            z_score=result.z_score,
            baseline_mean=result.baseline_mean,
            current_value=result.current_value,
        )