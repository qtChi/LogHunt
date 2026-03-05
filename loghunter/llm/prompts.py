# ==============================================================================
# loghunter/llm/prompts.py
#
# Centralised prompt templates for all LLM components.
#
# Per spec section 11.3 (Phase 3):
#   - INTENT_SYSTEM_PROMPT: static system prompt for IntentExtractor.
#   - build_intent_prompt():   user-turn prompt for NL → QueryIntent.
#   - build_anomaly_prompt():  prompt for AnomalyExplainer.
#   - build_sigma_prompt():    prompt for SigmaDraftGenerator.
#
# Keeping prompts here separates iteration concerns from business logic —
# prompts can be tuned without touching any engine or LLM class.
#
# Build Priority: Phase 3 — #2 in dependency order.
# ==============================================================================

from __future__ import annotations

# ---------------------------------------------------------------------------
# Intent extraction prompt
# ---------------------------------------------------------------------------

INTENT_SYSTEM_PROMPT: str = """
You are a security analyst assistant helping convert natural language log
queries into structured JSON for a SIEM query engine.

The SIEM stores OCSF events across these classes:
  1001 = File System Activity
  3001 = Network Activity
  3002 = HTTP Activity
  4001 = Process Activity
  6003 = Authentication Activity

You must respond ONLY with valid JSON matching this exact schema:
{
  "class_uid": <integer or null>,
  "filters": [
    {"field_path": "<ocsf.dot.path>", "operator": "<op>", "value": <value or null>}
  ],
  "time_range_hours": <integer or null>,
  "confidence": <float 0.0-1.0>
}

Valid operators: eq, ne, gt, lt, gte, lte, contains, is_null, not_null
Return null for fields you cannot confidently determine.
Do not include any explanation — JSON only.
""".strip()


def build_intent_prompt(natural_language: str) -> str:
    """
    Build the user-turn prompt for intent extraction.

    Args:
        natural_language: Raw analyst query string.

    Returns:
        Formatted prompt string.

    Raises:
        TypeError:  If natural_language is None.
        ValueError: If natural_language is empty/whitespace.
    """
    if natural_language is None:
        raise TypeError("natural_language must not be None")
    if not str(natural_language).strip():
        raise ValueError("natural_language must not be empty or whitespace")

    return f'Analyst query: "{natural_language.strip()}"'


# ---------------------------------------------------------------------------
# Anomaly explanation prompt
# ---------------------------------------------------------------------------

def build_anomaly_prompt(
    entity_type: str,
    entity_value: str,
    metric_name: str,
    current_value: float,
    baseline_mean: float,
    baseline_stddev: float,
    z_score: float,
    entity_context: dict,
) -> str:
    """
    Build the prompt for AnomalyExplainer.

    Args:
        entity_type:     e.g. "user", "ip"
        entity_value:    e.g. "jsmith", "10.0.0.1"
        metric_name:     e.g. "auth_count_per_hour"
        current_value:   Observed value triggering the anomaly
        baseline_mean:   Historical mean
        baseline_stddev: Historical standard deviation
        z_score:         Computed z-score
        entity_context:  Additional context dict for the entity

    Returns:
        Formatted prompt string.

    Raises:
        TypeError: If any required string arg is None.
    """
    if entity_type is None:
        raise TypeError("entity_type must not be None")
    if entity_value is None:
        raise TypeError("entity_value must not be None")
    if metric_name is None:
        raise TypeError("metric_name must not be None")

    context_str = (
        "\n".join(f"  {k}: {v}" for k, v in entity_context.items())
        if entity_context
        else "  (no additional context)"
    )

    return (
        f"You are a SOC analyst assistant.\n\n"
        f"An anomaly was detected:\n"
        f"  Entity:          {entity_type}={entity_value}\n"
        f"  Metric:          {metric_name}\n"
        f"  Current value:   {current_value:.4f}\n"
        f"  Baseline mean:   {baseline_mean:.4f}\n"
        f"  Baseline stddev: {baseline_stddev:.4f}\n"
        f"  Z-score:         {z_score:.2f}\n\n"
        f"Entity context:\n{context_str}\n\n"
        f"In 2-3 sentences, explain why this anomaly is notable and "
        f"what the analyst should investigate."
    )


# ---------------------------------------------------------------------------
# Sigma draft prompt
# ---------------------------------------------------------------------------

def build_sigma_prompt(
    event_fields: dict,
    mitre_techniques: list[str],
) -> str:
    """
    Build the prompt for SigmaDraftGenerator.

    Args:
        event_fields:     Dict of OCSF field_path → value (None values excluded).
        mitre_techniques: List of MITRE technique IDs e.g. ["T1078", "T1110"]

    Returns:
        Formatted prompt string instructing LLM to return YAML only.

    Raises:
        TypeError: If event_fields or mitre_techniques is None.
    """
    if event_fields is None:
        raise TypeError("event_fields must not be None")
    if mitre_techniques is None:
        raise TypeError("mitre_techniques must not be None")

    # Filter out None values before rendering
    clean_fields = {k: v for k, v in event_fields.items() if v is not None}

    fields_str = (
        "\n".join(f"  {k}: {v}" for k, v in clean_fields.items())
        if clean_fields
        else "  (no fields provided)"
    )

    techniques_str = (
        ", ".join(mitre_techniques)
        if mitre_techniques
        else "(none identified)"
    )

    return (
        f"You are a Sigma rule author specialising in SOC detection engineering.\n\n"
        f"Write a Sigma rule in valid YAML for the following security event.\n\n"
        f"Event fields (OCSF dot-notation):\n{fields_str}\n\n"
        f"Associated MITRE ATT&CK techniques: {techniques_str}\n\n"
        f"Requirements:\n"
        f"  - Output valid Sigma YAML only — no explanation, no markdown fences.\n"
        f"  - Include: title, status, description, logsource, detection, "
        f"falsepositives, level, tags.\n"
        f"  - Set tags to the ATT&CK technique IDs listed above.\n"
        f"  - Use 'condition: selection' with a 'selection:' block.\n"
        f"  - Set status to 'experimental'.\n"
    )