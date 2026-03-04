"""
SigmaDraftGenerator — Phase 2 LLM Layer
Generates Sigma YAML detection rule drafts using a local Ollama model.
Returns an empty Sigma YAML template if Ollama is unavailable (D-003).
Never raises.
"""
from __future__ import annotations

import logging
from typing import Any

from loghunter.config import LLM_MODEL
from loghunter.schema.ocsf_event import OCSFEvent

logger = logging.getLogger(__name__)

_EMPTY_SIGMA_TEMPLATE = """\
title: Untitled Detection Rule
id: ''
status: experimental
description: ''
references: []
author: ''
date: ''
logsource:
    product: ''
    service: ''
detection:
    selection:
        EventID: null
    condition: selection
falsepositives:
    - Unknown
level: medium
tags: []
"""


class SigmaDraftGenerator:
    """
    Generates draft Sigma YAML rules from an OCSFEvent and a list of
    matched MITRE ATT&CK technique IDs.

    Degrades gracefully: when Ollama is unavailable, returns
    ``_EMPTY_SIGMA_TEMPLATE`` so the analyst still gets a valid
    scaffold to edit (D-003).
    """

    def __init__(
        self,
        ollama_client: Any,
        model: str = LLM_MODEL,
    ) -> None:
        """
        Args:
            ollama_client: An ``ollama`` client instance.
            model:         Ollama model tag.

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

    def generate_draft(
        self,
        event: OCSFEvent,
        mitre_techniques: list[str],
    ) -> str:
        """
        Return a Sigma YAML draft string for the given event.

        Returns ``_EMPTY_SIGMA_TEMPLATE`` when Ollama is unavailable
        or any error occurs (D-003).  Never raises.

        Args:
            event:            The triggering OCSFEvent.
            mitre_techniques: MITRE ATT&CK technique IDs mapped to this
                              event (e.g. ["T1059.001", "T1078"]).
        """
        try:
            if event is None:
                return _EMPTY_SIGMA_TEMPLATE
            if not self._available:
                return _EMPTY_SIGMA_TEMPLATE

            prompt = self._build_prompt(event, mitre_techniques or [])
            response = self._client.chat(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
            )
            text = (
                response.get("message", {}).get("content", "")
                if isinstance(response, dict)
                else str(response)
            )
            result = text.strip()
            return result if result else _EMPTY_SIGMA_TEMPLATE
        except Exception as exc:
            logger.warning("SigmaDraftGenerator: Ollama call failed — %s", exc)
            self._available = False
            return _EMPTY_SIGMA_TEMPLATE

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _probe_availability(self) -> bool:
        try:
            self._client.list()
            return True
        except Exception as exc:
            logger.warning(
                "SigmaDraftGenerator: Ollama unavailable at init — %s", exc
            )
            return False

    @staticmethod
    def _build_prompt(event: OCSFEvent, mitre_techniques: list[str]) -> str:
        event_dict = event.to_dict()
        field_lines = "\n".join(
            f"  {k}: {v}"
            for k, v in event_dict.items()
            if v is not None
        )
        techniques_str = (
            ", ".join(mitre_techniques) if mitre_techniques else "none identified"
        )
        return (
            "You are a detection engineering assistant.\n\n"
            "Generate a Sigma detection rule in YAML format for the "
            "following security event.\n\n"
            f"Event fields:\n{field_lines}\n\n"
            f"MITRE ATT&CK techniques: {techniques_str}\n\n"
            "Return only valid Sigma YAML with no additional explanation. "
            "Include: title, id (UUID4), status: experimental, description, "
            "logsource, detection (selection + condition), falsepositives, "
            "level, and tags (mitre attack technique IDs)."
        )