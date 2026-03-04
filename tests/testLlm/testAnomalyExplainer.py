"""
tests/testLlm/testAnomalyExplainer.py
Tests for loghunter.llm.anomaly_explainer.AnomalyExplainer
Target: 100% branch coverage
"""
import pytest
from unittest.mock import MagicMock, patch

from loghunter.engine.anomaly import AnomalyResult
from loghunter.llm.anomaly_explainer import AnomalyExplainer, _PLACEHOLDER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_anomaly(
    z_score=5.0,
    is_anomaly=True,
    entity_type="user",
    entity_value="alice",
    metric_name="login_attempt_count",
    current_value=20.0,
    baseline_mean=10.0,
    baseline_stddev=2.0,
):
    return AnomalyResult(
        entity_type=entity_type,
        entity_value=entity_value,
        metric_name=metric_name,
        current_value=current_value,
        baseline_mean=baseline_mean,
        baseline_stddev=baseline_stddev,
        z_score=z_score,
        is_anomaly=is_anomaly,
    )


def _make_ollama(available=True, chat_response=None):
    m = MagicMock()
    if not available:
        m.list.side_effect = Exception("connection refused")
    else:
        m.list.return_value = {"models": []}
    if chat_response is not None:
        m.chat.return_value = {"message": {"content": chat_response}}
    else:
        m.chat.return_value = {"message": {"content": "This is suspicious."}}
    return m


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_client_raises(self):
        with pytest.raises(TypeError):
            AnomalyExplainer(None)

    def test_available_when_ollama_up(self):
        client = _make_ollama(available=True)
        explainer = AnomalyExplainer(client)
        assert explainer._available is True

    def test_unavailable_when_ollama_down(self):
        client = _make_ollama(available=False)
        explainer = AnomalyExplainer(client)
        assert explainer._available is False

    def test_custom_model_stored(self):
        client = _make_ollama()
        explainer = AnomalyExplainer(client, model="mistral")
        assert explainer._model == "mistral"

    def test_default_model_from_config(self):
        client = _make_ollama()
        with patch("loghunter.llm.anomaly_explainer.LLM_MODEL", "llama3"):
            explainer = AnomalyExplainer(client)
        assert explainer._model == "llama3"


# ---------------------------------------------------------------------------
# explain — unavailable paths (D-003)
# ---------------------------------------------------------------------------

class TestExplainUnavailable:
    def test_placeholder_when_unavailable(self):
        client = _make_ollama(available=False)
        explainer = AnomalyExplainer(client)
        anomaly = _make_anomaly()
        result = explainer.explain(anomaly, {})
        assert isinstance(result, str)
        assert len(result) > 0
        # Should not raise; should not be empty

    def test_placeholder_when_none_anomaly(self):
        client = _make_ollama(available=True)
        explainer = AnomalyExplainer(client)
        result = explainer.explain(None, {})
        assert "unavailable" in result.lower() or "no anomaly" in result.lower()

    def test_never_raises_on_chat_error(self):
        client = _make_ollama(available=True)
        client.chat.side_effect = Exception("timeout")
        explainer = AnomalyExplainer(client)
        anomaly = _make_anomaly()
        result = explainer.explain(anomaly, {})
        assert isinstance(result, str)
        assert explainer._available is False  # flipped to False after error

    def test_never_raises_on_bad_response(self):
        client = _make_ollama(available=True)
        client.chat.return_value = "not a dict"
        explainer = AnomalyExplainer(client)
        anomaly = _make_anomaly()
        result = explainer.explain(anomaly, {})
        # str response gets converted via str()
        assert isinstance(result, str)

    def test_empty_chat_response_returns_placeholder(self):
        client = _make_ollama(available=True)
        client.chat.return_value = {"message": {"content": "   "}}
        explainer = AnomalyExplainer(client)
        anomaly = _make_anomaly()
        result = explainer.explain(anomaly, {})
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# explain — available path
# ---------------------------------------------------------------------------

class TestExplainAvailable:
    def test_returns_ollama_response(self):
        client = _make_ollama(available=True, chat_response="Suspicious login spike.")
        explainer = AnomalyExplainer(client)
        anomaly = _make_anomaly()
        result = explainer.explain(anomaly, {"recent_events": 5})
        assert result == "Suspicious login spike."

    def test_chat_called_with_model(self):
        client = _make_ollama(available=True)
        explainer = AnomalyExplainer(client, model="llama3")
        anomaly = _make_anomaly()
        explainer.explain(anomaly, {})
        call_kwargs = client.chat.call_args[1]
        assert call_kwargs.get("model") == "llama3" or \
               client.chat.call_args[0][0] == "llama3" or \
               "llama3" in str(client.chat.call_args)

    def test_context_included_in_prompt(self):
        client = _make_ollama(available=True)
        explainer = AnomalyExplainer(client)
        anomaly = _make_anomaly()
        explainer.explain(anomaly, {"user_dept": "finance"})
        prompt = client.chat.call_args[1]["messages"][0]["content"]
        assert "finance" in prompt


# ---------------------------------------------------------------------------
# _build_prompt
# ---------------------------------------------------------------------------

class TestBuildPrompt:
    def test_contains_entity_info(self):
        anomaly = _make_anomaly(entity_type="ip", entity_value="1.2.3.4")
        prompt = AnomalyExplainer._build_prompt(anomaly, {})
        assert "ip=1.2.3.4" in prompt

    def test_contains_metric_name(self):
        anomaly = _make_anomaly(metric_name="net_bytes_out_per_hour")
        prompt = AnomalyExplainer._build_prompt(anomaly, {})
        assert "net_bytes_out_per_hour" in prompt

    def test_contains_z_score(self):
        anomaly = _make_anomaly(z_score=7.5)
        prompt = AnomalyExplainer._build_prompt(anomaly, {})
        assert "7.50" in prompt

    def test_empty_context_placeholder(self):
        anomaly = _make_anomaly()
        prompt = AnomalyExplainer._build_prompt(anomaly, {})
        assert "no additional context" in prompt

    def test_nonempty_context_rendered(self):
        anomaly = _make_anomaly()
        prompt = AnomalyExplainer._build_prompt(anomaly, {"dept": "hr"})
        assert "dept: hr" in prompt


# ---------------------------------------------------------------------------
# _placeholder
# ---------------------------------------------------------------------------

class TestPlaceholder:
    def test_none_anomaly_returns_string(self):
        result = AnomalyExplainer._placeholder(None)
        assert "no anomaly" in result.lower() or "unavailable" in result.lower()

    def test_non_none_anomaly_includes_metric(self):
        anomaly = _make_anomaly(metric_name="auth_count_per_hour")
        result = AnomalyExplainer._placeholder(anomaly)
        assert "auth_count_per_hour" in result