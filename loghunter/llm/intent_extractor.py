# ==============================================================================
# loghunter/llm/intent_extractor.py
#
# IntentExtractor — standout portfolio feature.
# Converts a plain-English analyst query into a QueryIntent via Ollama.
#
# Per spec section 11.4 (Phase 3):
#   - Follows D-003: LLM failure → returns QueryIntent(confidence=0.0),
#     never raises on Ollama errors.
#   - TypeError/ValueError on bad input arguments ARE raised — these
#     indicate programmer error, not LLM failure.
#   - Validates FilterIntent operators before constructing objects.
#   - _available flag tracks Ollama reachability, set False on any failure.
#
# Build Priority: Phase 3 — #3 in dependency order (after prompts, query_intent).
# ==============================================================================

from __future__ import annotations

import json
import logging
from typing import Optional

from loghunter import config
from loghunter.llm.prompts import INTENT_SYSTEM_PROMPT, build_intent_prompt
from loghunter.schema.query_intent import VALID_OPERATORS, FilterIntent, QueryIntent

logger = logging.getLogger(__name__)


class IntentExtractor:
    """
    Converts natural language analyst queries into QueryIntent objects
    using a local Ollama LLM.

    Per D-003: If Ollama is unavailable or returns unusable output,
    returns a minimal QueryIntent with the original text preserved
    and confidence=0.0. Never raises on LLM failure.
    """

    def __init__(
        self,
        ollama_client,
        model: Optional[str] = None,
    ) -> None:
        """
        Args:
            ollama_client: Initialised ollama.Client instance (or compatible
                           duck-type).
            model:         Model name override. Defaults to config.LLM_MODEL.

        Raises:
            TypeError: If ollama_client is None.
        """
        if ollama_client is None:
            raise TypeError("ollama_client must not be None")

        self._client = ollama_client
        self._model = model if model is not None else config.LLM_MODEL
        self._available = self._probe_availability()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, natural_language: str) -> QueryIntent:
        """
        Convert a natural language string to a QueryIntent.

        Process:
          1. Build prompt via prompts.build_intent_prompt()
          2. Call Ollama chat with INTENT_SYSTEM_PROMPT
          3. Parse JSON response into QueryIntent
          4. Validate FilterIntent operators against VALID_OPERATORS
          5. Return QueryIntent with confidence set from LLM response

        On any LLM failure (Ollama down, bad JSON, invalid fields):
          - Sets _available = False
          - Returns QueryIntent(natural_language=natural_language, confidence=0.0)
          - Never raises

        Args:
            natural_language: Raw analyst query string.

        Returns:
            QueryIntent — always returns, never raises on LLM failure.

        Raises:
            TypeError:  If natural_language is None.
            ValueError: If natural_language is empty/whitespace.
            (These ARE raised — programmer error, not LLM failure.)
        """
        # Input validation — these raise intentionally
        if natural_language is None:
            raise TypeError("natural_language must not be None")
        if not str(natural_language).strip():
            raise ValueError("natural_language must not be empty or whitespace")

        # D-003: all LLM work wrapped, never raises beyond this point
        try:
            if not self._available:
                return self._fallback(natural_language)

            prompt = build_intent_prompt(natural_language)
            response = self._client.chat(
                model=self._model,
                messages=[
                    {"role": "system", "content": INTENT_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )

            raw_text = self._extract_text(response)
            if not raw_text:
                logger.warning("IntentExtractor: empty response from Ollama")
                return self._fallback(natural_language)

            return self._parse_response(raw_text, natural_language)

        except Exception as exc:
            logger.warning("IntentExtractor: Ollama call failed — %s", exc)
            self._available = False
            return self._fallback(natural_language)

    def is_available(self) -> bool:
        """Return True if Ollama was reachable at last check."""
        return self._available

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
                "IntentExtractor: Ollama unavailable at init — %s", exc
            )
            return False

    @staticmethod
    def _extract_text(response) -> str:
        """
        Pull the content string from an Ollama response object.
        Handles both dict and object response shapes.
        Returns empty string on any failure.
        """
        try:
            if isinstance(response, dict):
                return response.get("message", {}).get("content", "")
            # Attribute-based response (ollama library object)
            return str(response.message.content)
        except Exception:
            return ""

    def _parse_response(self, raw_text: str, natural_language: str) -> QueryIntent:
        """
        Parse the LLM JSON response into a QueryIntent.
        Returns fallback QueryIntent on any parsing or validation error.
        """
        try:
            # Strip markdown fences if the model wrapped output
            clean = raw_text.strip()
            if clean.startswith("```"):
                lines = clean.splitlines()
                clean = "\n".join(
                    line for line in lines
                    if not line.strip().startswith("```")
                ).strip()

            data = json.loads(clean)

            class_uid = data.get("class_uid")  # None is acceptable
            time_range_hours = data.get("time_range_hours")  # None is acceptable
            raw_confidence = data.get("confidence")

            # Clamp confidence to valid range rather than reject
            confidence: Optional[float] = None
            if raw_confidence is not None:
                try:
                    confidence = max(0.0, min(1.0, float(raw_confidence)))
                except (TypeError, ValueError):
                    confidence = None

            # Build filters — skip any with invalid operators (D-003 spirit)
            filters: list[FilterIntent] = []
            for raw_filter in data.get("filters") or []:
                try:
                    field_path = raw_filter.get("field_path")
                    operator = raw_filter.get("operator")
                    value = raw_filter.get("value")

                    if operator not in VALID_OPERATORS:
                        logger.warning(
                            "IntentExtractor: skipping filter with unknown "
                            "operator '%s'", operator
                        )
                        continue

                    filters.append(
                        FilterIntent(
                            field_path=field_path,
                            operator=operator,
                            value=value,
                        )
                    )
                except Exception as filter_exc:
                    logger.warning(
                        "IntentExtractor: skipping malformed filter — %s",
                        filter_exc,
                    )
                    continue

            # Validate time_range_hours — must be int >= 1 or None
            if time_range_hours is not None:
                try:
                    time_range_hours = int(time_range_hours)
                    if time_range_hours < 1:
                        time_range_hours = None
                except (TypeError, ValueError):
                    time_range_hours = None

            return QueryIntent(
                natural_language=natural_language,
                class_uid=class_uid,
                filters=filters,
                time_range_hours=time_range_hours,
                confidence=confidence,
            )

        except Exception as exc:
            logger.warning(
                "IntentExtractor: failed to parse LLM response — %s", exc
            )
            self._available = False
            return self._fallback(natural_language)

    @staticmethod
    def _fallback(natural_language: str) -> QueryIntent:
        """Return a minimal QueryIntent signalling LLM degraded mode."""
        return QueryIntent(natural_language=natural_language, confidence=0.0)