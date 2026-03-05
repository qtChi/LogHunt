# ==============================================================================
# tests/testLlm/testPrompts.py
#
# 100% branch coverage for loghunter/llm/prompts.py
#
# Test strategy:
#   - INTENT_SYSTEM_PROMPT: structural content assertions.
#   - build_intent_prompt(): None → TypeError, empty/whitespace → ValueError,
#     happy path output shape.
#   - build_anomaly_prompt(): None args → TypeError for each required string,
#     happy path with context, happy path with empty context.
#   - build_sigma_prompt(): None args → TypeError, happy path with techniques,
#     empty techniques list, None values filtered from event_fields,
#     empty event_fields dict.
#   - pytest.raises always asserts on the specific exception subclass.
# ==============================================================================

from __future__ import annotations

import pytest

from loghunter.llm.prompts import (
    INTENT_SYSTEM_PROMPT,
    build_anomaly_prompt,
    build_intent_prompt,
    build_sigma_prompt,
)


# ===========================================================================
# INTENT_SYSTEM_PROMPT constant
# ===========================================================================

class TestIntentSystemPrompt:
    """Structural assertions — content must match LLM contract."""

    def test_is_string(self):
        assert isinstance(INTENT_SYSTEM_PROMPT, str)

    def test_not_empty(self):
        assert len(INTENT_SYSTEM_PROMPT.strip()) > 0

    def test_contains_all_five_class_uids(self):
        for uid in ("1001", "3001", "3002", "4001", "6003"):
            assert uid in INTENT_SYSTEM_PROMPT

    def test_contains_all_class_names(self):
        for name in (
            "File System Activity",
            "Network Activity",
            "HTTP Activity",
            "Process Activity",
            "Authentication Activity",
        ):
            assert name in INTENT_SYSTEM_PROMPT

    def test_contains_json_schema_keys(self):
        for key in ("class_uid", "filters", "field_path", "operator", "value",
                    "time_range_hours", "confidence"):
            assert key in INTENT_SYSTEM_PROMPT

    def test_contains_all_valid_operators(self):
        for op in ("eq", "ne", "gt", "lt", "gte", "lte",
                   "contains", "is_null", "not_null"):
            assert op in INTENT_SYSTEM_PROMPT

    def test_instructs_json_only_output(self):
        lower = INTENT_SYSTEM_PROMPT.lower()
        assert "json" in lower

    def test_no_trailing_whitespace_on_leading_lines(self):
        """Prompt should be stripped (no leading/trailing blank lines)."""
        assert INTENT_SYSTEM_PROMPT == INTENT_SYSTEM_PROMPT.strip()


# ===========================================================================
# build_intent_prompt()
# ===========================================================================

class TestBuildIntentPrompt:
    """Happy paths and error guards for build_intent_prompt()."""

    def test_returns_string(self):
        result = build_intent_prompt("show failed logins")
        assert isinstance(result, str)

    def test_output_contains_query_text(self):
        result = build_intent_prompt("show failed logins")
        assert "show failed logins" in result

    def test_output_strips_leading_trailing_whitespace_from_query(self):
        result = build_intent_prompt("  failed logins  ")
        assert "failed logins" in result
        # Leading/trailing spaces stripped in output
        assert "  failed logins  " not in result

    def test_single_word_query(self):
        result = build_intent_prompt("login")
        assert "login" in result

    def test_long_query_preserved(self):
        query = "show me all authentication failures from 10.0.0.1 in the last 24 hours"
        result = build_intent_prompt(query)
        assert query.strip() in result

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError, match="natural_language must not be None"):
            build_intent_prompt(None)

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError, match="natural_language must not be empty"):
            build_intent_prompt("")

    def test_whitespace_only_raises_value_error(self):
        with pytest.raises(ValueError, match="natural_language must not be empty"):
            build_intent_prompt("   ")

    def test_tab_only_raises_value_error(self):
        with pytest.raises(ValueError):
            build_intent_prompt("\t")

    def test_newline_only_raises_value_error(self):
        with pytest.raises(ValueError):
            build_intent_prompt("\n")


# ===========================================================================
# build_anomaly_prompt()
# ===========================================================================

class TestBuildAnomalyPrompt:
    """Happy paths and TypeError guards for build_anomaly_prompt()."""

    # --- Helpers ---

    def _default_kwargs(self, **overrides):
        kwargs = dict(
            entity_type="user",
            entity_value="jsmith",
            metric_name="auth_count_per_hour",
            current_value=42.0,
            baseline_mean=5.0,
            baseline_stddev=1.5,
            z_score=4.2,
            entity_context={"dept": "engineering", "location": "US"},
        )
        kwargs.update(overrides)
        return kwargs

    # --- Happy paths ---

    def test_returns_string(self):
        result = build_anomaly_prompt(**self._default_kwargs())
        assert isinstance(result, str)

    def test_output_contains_entity_type_and_value(self):
        result = build_anomaly_prompt(**self._default_kwargs())
        assert "user" in result
        assert "jsmith" in result

    def test_output_contains_metric_name(self):
        result = build_anomaly_prompt(**self._default_kwargs())
        assert "auth_count_per_hour" in result

    def test_output_contains_numeric_values(self):
        result = build_anomaly_prompt(**self._default_kwargs())
        assert "42.0000" in result
        assert "5.0000" in result
        assert "1.5000" in result
        assert "4.20" in result

    def test_output_contains_context_keys_and_values(self):
        result = build_anomaly_prompt(**self._default_kwargs())
        assert "dept" in result
        assert "engineering" in result
        assert "location" in result
        assert "US" in result

    def test_empty_context_dict_renders_placeholder(self):
        result = build_anomaly_prompt(**self._default_kwargs(entity_context={}))
        assert "no additional context" in result

    def test_none_context_renders_placeholder(self):
        result = build_anomaly_prompt(**self._default_kwargs(entity_context=None))
        assert "no additional context" in result

    def test_output_contains_soc_instruction(self):
        result = build_anomaly_prompt(**self._default_kwargs())
        lower = result.lower()
        assert "soc" in lower or "analyst" in lower

    def test_output_contains_investigate_instruction(self):
        result = build_anomaly_prompt(**self._default_kwargs())
        assert "investigate" in result.lower()

    def test_zero_values_formatted_correctly(self):
        result = build_anomaly_prompt(**self._default_kwargs(
            current_value=0.0, baseline_mean=0.0, baseline_stddev=0.0, z_score=0.0
        ))
        assert "0.0000" in result

    def test_negative_z_score_formatted(self):
        result = build_anomaly_prompt(**self._default_kwargs(z_score=-3.5))
        assert "-3.50" in result

    # --- TypeError guards ---

    def test_entity_type_none_raises_type_error(self):
        with pytest.raises(TypeError, match="entity_type must not be None"):
            build_anomaly_prompt(**self._default_kwargs(entity_type=None))

    def test_entity_value_none_raises_type_error(self):
        with pytest.raises(TypeError, match="entity_value must not be None"):
            build_anomaly_prompt(**self._default_kwargs(entity_value=None))

    def test_metric_name_none_raises_type_error(self):
        with pytest.raises(TypeError, match="metric_name must not be None"):
            build_anomaly_prompt(**self._default_kwargs(metric_name=None))


# ===========================================================================
# build_sigma_prompt()
# ===========================================================================

class TestBuildSigmaPrompt:
    """Happy paths, None filtering, and TypeError guards for build_sigma_prompt()."""

    # --- Happy paths ---

    def test_returns_string(self):
        result = build_sigma_prompt(
            event_fields={"actor.user.name": "admin", "severity_id": 3},
            mitre_techniques=["T1078"],
        )
        assert isinstance(result, str)

    def test_output_contains_field_paths_and_values(self):
        result = build_sigma_prompt(
            event_fields={"actor.user.name": "admin", "severity_id": 3},
            mitre_techniques=["T1078"],
        )
        assert "actor.user.name" in result
        assert "admin" in result
        assert "severity_id" in result
        assert "3" in result

    def test_output_contains_technique_ids(self):
        result = build_sigma_prompt(
            event_fields={"severity_id": 3},
            mitre_techniques=["T1078", "T1110"],
        )
        assert "T1078" in result
        assert "T1110" in result

    def test_output_instructs_yaml_only(self):
        result = build_sigma_prompt(
            event_fields={"severity_id": 1},
            mitre_techniques=["T1059"],
        )
        assert "YAML" in result or "yaml" in result.lower()

    def test_output_contains_required_sigma_keys(self):
        result = build_sigma_prompt(
            event_fields={"severity_id": 1},
            mitre_techniques=["T1059"],
        )
        for key in ("title", "description", "logsource", "detection",
                    "falsepositives", "level", "tags"):
            assert key in result

    def test_none_values_filtered_from_event_fields(self):
        result = build_sigma_prompt(
            event_fields={"actor.user.name": "jsmith", "dst_endpoint.ip": None},
            mitre_techniques=["T1078"],
        )
        assert "actor.user.name" in result
        assert "jsmith" in result
        # None-valued field should not appear
        assert "dst_endpoint.ip" not in result

    def test_all_none_values_renders_placeholder(self):
        result = build_sigma_prompt(
            event_fields={"field_a": None, "field_b": None},
            mitre_techniques=["T1078"],
        )
        assert "no fields provided" in result

    def test_empty_event_fields_dict_renders_placeholder(self):
        result = build_sigma_prompt(
            event_fields={},
            mitre_techniques=["T1078"],
        )
        assert "no fields provided" in result

    def test_empty_techniques_list_renders_placeholder(self):
        result = build_sigma_prompt(
            event_fields={"severity_id": 1},
            mitre_techniques=[],
        )
        assert "none identified" in result

    def test_multiple_techniques_comma_separated(self):
        result = build_sigma_prompt(
            event_fields={"severity_id": 1},
            mitre_techniques=["T1059", "T1059.001", "T1078"],
        )
        assert "T1059" in result
        assert "T1059.001" in result
        assert "T1078" in result

    def test_status_experimental_in_output(self):
        result = build_sigma_prompt(
            event_fields={"severity_id": 1},
            mitre_techniques=["T1078"],
        )
        assert "experimental" in result

    def test_condition_selection_in_output(self):
        result = build_sigma_prompt(
            event_fields={"severity_id": 1},
            mitre_techniques=["T1078"],
        )
        assert "selection" in result

    # --- TypeError guards ---

    def test_event_fields_none_raises_type_error(self):
        with pytest.raises(TypeError, match="event_fields must not be None"):
            build_sigma_prompt(event_fields=None, mitre_techniques=["T1078"])

    def test_mitre_techniques_none_raises_type_error(self):
        with pytest.raises(TypeError, match="mitre_techniques must not be None"):
            build_sigma_prompt(
                event_fields={"severity_id": 1},
                mitre_techniques=None,
            )