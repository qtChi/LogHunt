"""
tests/testLlm/testSigmaDraftGenerator.py
Tests for loghunter.llm.sigma_draft_generator.SigmaDraftGenerator
Target: 100% branch coverage
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from loghunter.llm.sigma_draft_generator import (
    SigmaDraftGenerator,
    _EMPTY_SIGMA_TEMPLATE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ollama(available=True, chat_response=None):
    m = MagicMock()
    if not available:
        m.list.side_effect = Exception("connection refused")
    else:
        m.list.return_value = {"models": []}
    m.chat.return_value = {
        "message": {
            "content": chat_response
            or "title: Test\ndetection:\n  condition: selection\n"
        }
    }
    return m


def _make_event():
    e = MagicMock()
    e.to_dict.return_value = {
        "class_uid": 6003,
        "activity_id": 2,
        "severity_id": 3,
        "time": "2026-01-01T00:00:00Z",
        "metadata.log_source": "evtx",
        "metadata.original_time": "2026-01-01T00:00:00Z",
        "actor.user.name": "baduser",
    }
    return e


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_client_raises(self):
        with pytest.raises(TypeError):
            SigmaDraftGenerator(None)

    def test_available_when_ollama_up(self):
        client = _make_ollama(available=True)
        gen = SigmaDraftGenerator(client)
        assert gen._available is True

    def test_unavailable_when_ollama_down(self):
        client = _make_ollama(available=False)
        gen = SigmaDraftGenerator(client)
        assert gen._available is False

    def test_custom_model_stored(self):
        client = _make_ollama()
        gen = SigmaDraftGenerator(client, model="codellama")
        assert gen._model == "codellama"

    def test_default_model_from_config(self):
        client = _make_ollama()
        with patch("loghunter.llm.sigma_draft_generator.LLM_MODEL", "llama3"):
            gen = SigmaDraftGenerator(client)
        assert gen._model == "llama3"


# ---------------------------------------------------------------------------
# generate_draft — unavailable paths (D-003)
# ---------------------------------------------------------------------------

class TestGenerateDraftUnavailable:
    def test_template_when_unavailable(self):
        client = _make_ollama(available=False)
        gen = SigmaDraftGenerator(client)
        result = gen.generate_draft(_make_event(), ["T1078"])
        assert result == _EMPTY_SIGMA_TEMPLATE

    def test_template_when_none_event(self):
        client = _make_ollama(available=True)
        gen = SigmaDraftGenerator(client)
        result = gen.generate_draft(None, ["T1078"])
        assert result == _EMPTY_SIGMA_TEMPLATE

    def test_never_raises_on_chat_exception(self):
        client = _make_ollama(available=True)
        client.chat.side_effect = Exception("LLM offline")
        gen = SigmaDraftGenerator(client)
        result = gen.generate_draft(_make_event(), [])
        assert result == _EMPTY_SIGMA_TEMPLATE
        assert gen._available is False

    def test_template_when_empty_chat_response(self):
        client = _make_ollama(available=True)
        client.chat.return_value = {"message": {"content": "   "}}
        gen = SigmaDraftGenerator(client)
        result = gen.generate_draft(_make_event(), [])
        assert result == _EMPTY_SIGMA_TEMPLATE

    def test_non_dict_response_handled(self):
        client = _make_ollama(available=True)
        client.chat.return_value = "plain string"
        gen = SigmaDraftGenerator(client)
        result = gen.generate_draft(_make_event(), [])
        assert isinstance(result, str)

    def test_none_techniques_uses_empty_list(self):
        client = _make_ollama(available=False)
        gen = SigmaDraftGenerator(client)
        # Should not raise even if mitre_techniques is None-like (handled in generate_draft)
        result = gen.generate_draft(_make_event(), None)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# generate_draft — available path
# ---------------------------------------------------------------------------

class TestGenerateDraftAvailable:
    def test_returns_ollama_yaml(self):
        yaml = "title: My Rule\ndetection:\n  condition: selection\n"
        client = _make_ollama(available=True, chat_response=yaml)
        gen = SigmaDraftGenerator(client)
        result = gen.generate_draft(_make_event(), ["T1059.001"])
        assert result == yaml.strip()

    def test_chat_called_with_model(self):
        client = _make_ollama(available=True)
        gen = SigmaDraftGenerator(client, model="mistral")
        gen.generate_draft(_make_event(), ["T1078"])
        assert client.chat.called

    def test_techniques_in_prompt(self):
        client = _make_ollama(available=True)
        gen = SigmaDraftGenerator(client)
        gen.generate_draft(_make_event(), ["T1059.001", "T1078"])
        call_args = client.chat.call_args
        messages = call_args[1]["messages"]
        prompt = messages[0]["content"]
        assert "T1059.001" in prompt
        assert "T1078" in prompt

    def test_event_fields_in_prompt(self):
        client = _make_ollama(available=True)
        gen = SigmaDraftGenerator(client)
        gen.generate_draft(_make_event(), [])
        prompt = client.chat.call_args[1]["messages"][0]["content"]
        assert "baduser" in prompt or "actor.user.name" in prompt


# ---------------------------------------------------------------------------
# _build_prompt
# ---------------------------------------------------------------------------

class TestBuildPrompt:
    def test_contains_event_fields(self):
        event = _make_event()
        prompt = SigmaDraftGenerator._build_prompt(event, ["T1078"])
        assert "baduser" in prompt

    def test_contains_technique_ids(self):
        event = _make_event()
        prompt = SigmaDraftGenerator._build_prompt(event, ["T1059", "T1110"])
        assert "T1059" in prompt
        assert "T1110" in prompt

    def test_empty_techniques_shows_none_identified(self):
        event = _make_event()
        prompt = SigmaDraftGenerator._build_prompt(event, [])
        assert "none identified" in prompt

    def test_none_field_values_excluded(self):
        event = MagicMock()
        event.to_dict.return_value = {
            "class_uid": 6003,
            "actor.user.name": None,
            "metadata.log_source": "evtx",
        }
        prompt = SigmaDraftGenerator._build_prompt(event, [])
        assert "actor.user.name" not in prompt
        assert "evtx" in prompt

    def test_instructs_yaml_only_output(self):
        event = _make_event()
        prompt = SigmaDraftGenerator._build_prompt(event, [])
        assert "YAML" in prompt or "yaml" in prompt.lower()


# ---------------------------------------------------------------------------
# _EMPTY_SIGMA_TEMPLATE structure
# ---------------------------------------------------------------------------

class TestEmptySigmaTemplate:
    def test_has_required_keys(self):
        assert "title:" in _EMPTY_SIGMA_TEMPLATE
        assert "status:" in _EMPTY_SIGMA_TEMPLATE
        assert "detection:" in _EMPTY_SIGMA_TEMPLATE
        assert "level:" in _EMPTY_SIGMA_TEMPLATE

    def test_is_string(self):
        assert isinstance(_EMPTY_SIGMA_TEMPLATE, str)