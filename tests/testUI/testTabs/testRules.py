# tests/testUI/testRules.py — 100% branch coverage for ui/tabs/rules.py pure functions
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()

import pytest
from loghunter.ui.tabs.rules import (
    validate_sigma_yaml, store_and_log, confirm_and_log, export_and_return
)

_VALID_SIGMA = """
title: Test Rule
status: experimental
description: Test
logsource:
  category: process_creation
detection:
  selection:
    CommandLine: malware
  condition: selection
falsepositives: []
level: high
"""

class TestValidateSigmaYaml:
    def test_valid_yaml_returns_true(self):
        ok, err = validate_sigma_yaml(_VALID_SIGMA)
        assert ok is True and err == ""

    def test_missing_title_returns_false(self):
        yaml = "detection:\n  selection:\n    k: v\n  condition: selection\n"
        ok, err = validate_sigma_yaml(yaml)
        assert ok is False and "title" in err

    def test_missing_detection_returns_false(self):
        yaml = "title: Test\nstatus: experimental\n"
        ok, err = validate_sigma_yaml(yaml)
        assert ok is False and "detection" in err

    def test_invalid_yaml_returns_false(self):
        ok, err = validate_sigma_yaml("{{{{not valid yaml")
        assert ok is False and err != ""

    def test_non_mapping_yaml_returns_false(self):
        ok, err = validate_sigma_yaml("- item1\n- item2\n")
        assert ok is False and "mapping" in err


class TestStoreAndLog:
    def test_success(self):
        sigma = MagicMock()
        result = store_and_log("rule1", _VALID_SIGMA, sigma)
        assert result["success"] is True and result["rule_id"] == "rule1"
        sigma.store_rule.assert_called_once_with("rule1", _VALID_SIGMA)

    def test_exception_returns_error(self):
        sigma = MagicMock()
        sigma.store_rule.side_effect = ValueError("bad rule")
        result = store_and_log("rule1", _VALID_SIGMA, sigma)
        assert result["success"] is False and "bad rule" in result["error"]


class TestConfirmAndLog:
    def test_success(self):
        sigma = MagicMock()
        result = confirm_and_log("rule1", "session-1", sigma)
        assert result["success"] is True and result["error"] is None

    def test_not_found_returns_error(self):
        sigma = MagicMock()
        sigma.confirm_rule.side_effect = ValueError("not found")
        result = confirm_and_log("bad_rule", None, sigma)
        assert result["success"] is False and "not found" in result["error"]


class TestExportAndReturn:
    def test_success(self):
        sigma = MagicMock()
        sigma.export_rule.return_value = _VALID_SIGMA
        result = export_and_return("rule1", sigma)
        assert result["success"] is True and result["yaml_content"] == _VALID_SIGMA

    def test_not_confirmed_returns_error(self):
        sigma = MagicMock()
        sigma.export_rule.side_effect = ValueError("not confirmed")
        result = export_and_return("rule1", sigma)
        assert result["success"] is False and "not confirmed" in result["error"]