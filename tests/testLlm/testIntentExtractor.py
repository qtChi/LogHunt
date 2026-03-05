# ==============================================================================
# tests/testLlm/testIntentExtractor.py
#
# 100% branch coverage for loghunter/llm/intent_extractor.py
#
# Test strategy:
#   - Construction: None client → TypeError; probe success/failure branches.
#   - extract(): TypeError on None, ValueError on empty/whitespace.
#   - D-003 paths: Ollama down at init, Ollama down at call time,
#     bad JSON, empty response, valid JSON → full QueryIntent.
#   - Filter parsing: valid operator kept, unknown operator skipped,
#     malformed filter skipped, None value preserved.
#   - Confidence clamping: above 1.0 clamped, below 0.0 clamped, None ok.
#   - time_range_hours: < 1 → None, non-integer → None, valid int kept.
#   - Markdown fence stripping in raw response.
#   - is_available(): reflects _available flag.
#   - All Ollama interactions mocked — zero real network calls.
# ==============================================================================

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from loghunter.llm.intent_extractor import IntentExtractor
from loghunter.schema.query_intent import FilterIntent, QueryIntent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(list_raises=False, chat_response=None, chat_raises=False):
    """Build a mock ollama client."""
    client = MagicMock()
    if list_raises:
        client.list.side_effect = ConnectionRefusedError("Ollama down")
    else:
        client.list.return_value = {"models": []}

    if chat_raises:
        client.chat.side_effect = ConnectionRefusedError("Ollama down")
    elif chat_response is not None:
        client.chat.return_value = chat_response
    return client


def _dict_response(content: str) -> dict:
    """Build a dict-style Ollama chat response."""
    return {"message": {"content": content}}


def _obj_response(content: str):
    """Build an object-style Ollama chat response."""
    resp = MagicMock()
    resp.message.content = content
    return resp


def _json_payload(
    class_uid=6003,
    filters=None,
    time_range_hours=24,
    confidence=0.85,
) -> str:
    return json.dumps({
        "class_uid": class_uid,
        "filters": filters or [],
        "time_range_hours": time_range_hours,
        "confidence": confidence,
    })


# ===========================================================================
# Construction
# ===========================================================================

class TestIntentExtractorConstruction:

    def test_none_client_raises_type_error(self):
        with pytest.raises(TypeError, match="ollama_client must not be None"):
            IntentExtractor(ollama_client=None)

    def test_available_true_when_probe_succeeds(self):
        client = _make_client()
        ie = IntentExtractor(client)
        assert ie.is_available() is True

    def test_available_false_when_probe_fails(self):
        client = _make_client(list_raises=True)
        ie = IntentExtractor(client)
        assert ie.is_available() is False

    def test_default_model_from_config(self):
        client = _make_client()
        with patch("loghunter.llm.intent_extractor.config") as mock_cfg:
            mock_cfg.LLM_MODEL = "llama3"
            ie = IntentExtractor(client)
        assert ie._model == "llama3"

    def test_model_override_respected(self):
        client = _make_client()
        ie = IntentExtractor(client, model="mistral")
        assert ie._model == "mistral"

    def test_none_model_falls_back_to_config(self):
        client = _make_client()
        with patch("loghunter.llm.intent_extractor.config") as mock_cfg:
            mock_cfg.LLM_MODEL = "codellama"
            ie = IntentExtractor(client, model=None)
        assert ie._model == "codellama"


# ===========================================================================
# extract() — input validation (these DO raise)
# ===========================================================================

class TestExtractInputValidation:

    def setup_method(self):
        self.ie = IntentExtractor(_make_client())

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError, match="natural_language must not be None"):
            self.ie.extract(None)

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError, match="natural_language must not be empty"):
            self.ie.extract("")

    def test_whitespace_only_raises_value_error(self):
        with pytest.raises(ValueError):
            self.ie.extract("   ")

    def test_tab_only_raises_value_error(self):
        with pytest.raises(ValueError):
            self.ie.extract("\t")


# ===========================================================================
# extract() — D-003 degraded paths
# ===========================================================================

class TestExtractDegradedPaths:

    def test_unavailable_at_init_returns_fallback(self):
        client = _make_client(list_raises=True)
        ie = IntentExtractor(client)
        result = ie.extract("show failed logins")
        assert isinstance(result, QueryIntent)
        assert result.confidence == 0.0
        assert result.natural_language == "show failed logins"
        assert result.class_uid is None

    def test_ollama_down_at_call_time_returns_fallback(self):
        client = _make_client(chat_raises=True)
        ie = IntentExtractor(client)
        assert ie.is_available() is True
        result = ie.extract("show failed logins")
        assert result.confidence == 0.0
        assert ie.is_available() is False

    def test_empty_response_returns_fallback(self):
        client = _make_client(chat_response=_dict_response(""))
        ie = IntentExtractor(client)
        result = ie.extract("any query")
        assert result.confidence == 0.0

    def test_bad_json_returns_fallback(self):
        client = _make_client(chat_response=_dict_response("not json at all"))
        ie = IntentExtractor(client)
        result = ie.extract("any query")
        assert result.confidence == 0.0

    def test_json_missing_keys_uses_none_defaults(self):
        """Partial JSON — missing keys should yield None, not raise."""
        client = _make_client(chat_response=_dict_response('{}'))
        ie = IntentExtractor(client)
        result = ie.extract("any query")
        assert isinstance(result, QueryIntent)
        assert result.class_uid is None
        assert result.filters == []
        assert result.time_range_hours is None

    def test_natural_language_preserved_on_fallback(self):
        client = _make_client(list_raises=True)
        ie = IntentExtractor(client)
        nl = "find all brute force attempts"
        result = ie.extract(nl)
        assert result.natural_language == nl


# ===========================================================================
# extract() — successful parse paths
# ===========================================================================

class TestExtractSuccessPaths:

    def _ie(self, response_content: str) -> IntentExtractor:
        client = _make_client(chat_response=_dict_response(response_content))
        return IntentExtractor(client)

    def test_class_uid_extracted(self):
        ie = self._ie(_json_payload(class_uid=6003))
        result = ie.extract("auth failures")
        assert result.class_uid == 6003

    def test_class_uid_none_accepted(self):
        ie = self._ie(_json_payload(class_uid=None))
        result = ie.extract("auth failures")
        assert result.class_uid is None

    def test_confidence_extracted(self):
        ie = self._ie(_json_payload(confidence=0.75))
        result = ie.extract("auth failures")
        assert result.confidence == 0.75

    def test_time_range_hours_extracted(self):
        ie = self._ie(_json_payload(time_range_hours=48))
        result = ie.extract("last 48 hours")
        assert result.time_range_hours == 48

    def test_natural_language_preserved_on_success(self):
        ie = self._ie(_json_payload())
        nl = "show me failed logins"
        result = ie.extract(nl)
        assert result.natural_language == nl

    def test_valid_filter_extracted(self):
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [
                {"field_path": "severity_id", "operator": "gte", "value": 3}
            ],
            "time_range_hours": 24,
            "confidence": 0.9,
        })
        ie = self._ie(payload)
        result = ie.extract("high severity auth")
        assert len(result.filters) == 1
        assert result.filters[0].field_path == "severity_id"
        assert result.filters[0].operator == "gte"
        assert result.filters[0].value == 3

    def test_multiple_valid_filters_extracted(self):
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [
                {"field_path": "severity_id", "operator": "gte", "value": 3},
                {"field_path": "actor.user.name", "operator": "eq", "value": "admin"},
            ],
            "time_range_hours": 24,
            "confidence": 0.8,
        })
        ie = self._ie(payload)
        result = ie.extract("admin high severity")
        assert len(result.filters) == 2

    def test_filter_with_null_value_preserved(self):
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [
                {"field_path": "actor.user.name", "operator": "is_null", "value": None}
            ],
            "time_range_hours": None,
            "confidence": 0.7,
        })
        ie = self._ie(payload)
        result = ie.extract("missing user name")
        assert len(result.filters) == 1
        assert result.filters[0].value is None

    def test_object_style_response_handled(self):
        """Ollama library returns attribute-based objects, not just dicts."""
        client = _make_client(chat_response=_obj_response(_json_payload()))
        ie = IntentExtractor(client)
        result = ie.extract("test")
        assert isinstance(result, QueryIntent)

    def test_markdown_fenced_json_stripped(self):
        fenced = "```json\n" + _json_payload(class_uid=3001) + "\n```"
        ie = self._ie(fenced)
        result = ie.extract("network connections")
        assert result.class_uid == 3001

    def test_plain_markdown_fence_stripped(self):
        fenced = "```\n" + _json_payload(class_uid=3002) + "\n```"
        ie = self._ie(fenced)
        result = ie.extract("http activity")
        assert result.class_uid == 3002


# ===========================================================================
# extract() — filter edge cases
# ===========================================================================

class TestExtractFilterEdgeCases:

    def _ie(self, payload: str) -> IntentExtractor:
        client = _make_client(chat_response=_dict_response(payload))
        return IntentExtractor(client)

    def test_unknown_operator_skipped(self):
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [
                {"field_path": "severity_id", "operator": "LIKE", "value": "3"},
                {"field_path": "activity_id", "operator": "eq", "value": 1},
            ],
            "time_range_hours": 24,
            "confidence": 0.8,
        })
        ie = self._ie(payload)
        result = ie.extract("test")
        # LIKE should be skipped, eq kept
        assert len(result.filters) == 1
        assert result.filters[0].operator == "eq"

    def test_all_filters_with_bad_operators_yields_empty_list(self):
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [
                {"field_path": "severity_id", "operator": "INVALID"},
                {"field_path": "activity_id", "operator": "ALSO_BAD"},
            ],
            "time_range_hours": None,
            "confidence": 0.6,
        })
        ie = self._ie(payload)
        result = ie.extract("test")
        assert result.filters == []

    def test_malformed_filter_dict_skipped(self):
        """Filter missing field_path — FilterIntent will raise, should be skipped."""
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [
                {"operator": "eq", "value": 1},   # missing field_path → None → TypeError
                {"field_path": "activity_id", "operator": "eq", "value": 1},
            ],
            "time_range_hours": None,
            "confidence": 0.7,
        })
        ie = self._ie(payload)
        result = ie.extract("test")
        # First filter skipped, second kept
        assert len(result.filters) == 1
        assert result.filters[0].field_path == "activity_id"

    def test_empty_filters_list_in_response(self):
        payload = _json_payload(filters=[])
        ie = self._ie(payload)
        result = ie.extract("test")
        assert result.filters == []

    def test_null_filters_in_response(self):
        payload = json.dumps({
            "class_uid": 6003,
            "filters": None,
            "time_range_hours": 24,
            "confidence": 0.5,
        })
        ie = self._ie(payload)
        result = ie.extract("test")
        assert result.filters == []


# ===========================================================================
# extract() — confidence clamping
# ===========================================================================

class TestExtractConfidenceClamping:

    def _ie(self, confidence) -> IntentExtractor:
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [],
            "time_range_hours": 24,
            "confidence": confidence,
        })
        client = _make_client(chat_response=_dict_response(payload))
        return IntentExtractor(client)

    def test_confidence_above_one_clamped_to_one(self):
        result = self._ie(1.5).extract("test")
        assert result.confidence == 1.0

    def test_confidence_below_zero_clamped_to_zero(self):
        result = self._ie(-0.5).extract("test")
        assert result.confidence == 0.0

    def test_confidence_exactly_zero_kept(self):
        result = self._ie(0.0).extract("test")
        assert result.confidence == 0.0

    def test_confidence_exactly_one_kept(self):
        result = self._ie(1.0).extract("test")
        assert result.confidence == 1.0

    def test_confidence_null_in_response_yields_none(self):
        result = self._ie(None).extract("test")
        assert result.confidence is None

    def test_confidence_non_numeric_yields_none(self):
        result = self._ie("high").extract("test")
        assert result.confidence is None


# ===========================================================================
# extract() — time_range_hours edge cases
# ===========================================================================

class TestExtractTimeRangeEdgeCases:

    def _ie(self, time_range_hours) -> IntentExtractor:
        payload = json.dumps({
            "class_uid": 6003,
            "filters": [],
            "time_range_hours": time_range_hours,
            "confidence": 0.8,
        })
        client = _make_client(chat_response=_dict_response(payload))
        return IntentExtractor(client)

    def test_zero_time_range_becomes_none(self):
        result = self._ie(0).extract("test")
        assert result.time_range_hours is None

    def test_negative_time_range_becomes_none(self):
        result = self._ie(-5).extract("test")
        assert result.time_range_hours is None

    def test_valid_time_range_preserved(self):
        result = self._ie(24).extract("test")
        assert result.time_range_hours == 24

    def test_float_time_range_converted_to_int(self):
        result = self._ie(12.0).extract("test")
        assert result.time_range_hours == 12

    def test_non_numeric_time_range_becomes_none(self):
        result = self._ie("last week").extract("test")
        assert result.time_range_hours is None

    def test_none_time_range_preserved(self):
        result = self._ie(None).extract("test")
        assert result.time_range_hours is None


# ===========================================================================
# is_available()
# ===========================================================================

class TestIsAvailable:

    def test_true_after_successful_probe(self):
        ie = IntentExtractor(_make_client())
        assert ie.is_available() is True

    def test_false_after_failed_probe(self):
        ie = IntentExtractor(_make_client(list_raises=True))
        assert ie.is_available() is False

    def test_flips_to_false_after_chat_failure(self):
        client = _make_client(chat_raises=True)
        ie = IntentExtractor(client)
        assert ie.is_available() is True
        ie.extract("test")
        assert ie.is_available() is False