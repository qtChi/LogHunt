# ==============================================================================
# tests/testEngine/testMitreMapper.py
#
# Tests for loghunter/engine/mitre_mapper.py
#
# Coverage strategy — every branch explicitly targeted:
#
# Constructor:
#   All supported classes indexed
#   Rules indexed by class_uid only
#
# map_event:
#   None event → TypeError
#   Event with no matching rules → []
#   Event matching single rule → [technique_id]
#   Event matching multiple rules → all IDs returned
#   Predicate raising exception → rule skipped, no raise (D-006)
#   Class with no rules → []
#
# get_coverage:
#   Returns dict keyed by all supported classes
#   Classes with rules have non-empty sets
#   Classes with no rules have empty sets
#
# get_rules_for_class:
#   Supported class with rules → non-empty list
#   Unsupported class → empty list
#   Return is a copy
#
# Helper functions (_field, _eq, _contains, _gt, _not_none):
#   _field: valid path, None path, exception path
#   _eq: match, no match, None value
#   _contains: match, no match, None value, exception
#   _gt: above threshold, below, None, non-numeric
#   _not_none: set field, None field
#
# MappingRule:
#   frozen / immutable
#
# Built-in rules:
#   T1078, T1110, T1110.001, T1078.002 (auth)
#   T1059, T1059.001, T1055, T1053 (process)
#   T1071, T1048, T1090, T1046 (network)
#   T1190, T1059.007 (http)
#   T1005, T1070.004 (file)
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from loghunter.engine.mitre_mapper import (
    MappingRule,
    MitreMapper,
    _contains,
    _eq,
    _field,
    _gt,
    _not_none,
)
from loghunter.schema.ocsf_field_registry import SUPPORTED_CLASSES
from loghunter.schema.ocsf_event import OCSFEvent

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make(ocsf_registry, class_uid=6003, activity_id=1,
          severity_id=1, **fields):
    event = OCSFEvent(
        class_uid=class_uid,
        activity_id=activity_id,
        severity_id=severity_id,
        time=T0,
        metadata_log_source="test",
        metadata_original_time="2026-01-01T00:00:00Z",
        registry=ocsf_registry,
    )
    for k, v in fields.items():
        event._fields[k] = v
    return event


# ==============================================================================
# TestMitreMapperConstructor
# ==============================================================================

class TestMitreMapperConstructor:

    def test_constructs_without_error(self):
        assert MitreMapper() is not None

    def test_all_supported_classes_indexed(self):
        mapper = MitreMapper()
        coverage = mapper.get_coverage()
        assert set(coverage.keys()) == SUPPORTED_CLASSES

    def test_auth_class_has_rules(self):
        mapper = MitreMapper()
        assert len(mapper.get_rules_for_class(6003)) > 0

    def test_process_class_has_rules(self):
        mapper = MitreMapper()
        assert len(mapper.get_rules_for_class(4001)) > 0

    def test_network_class_has_rules(self):
        mapper = MitreMapper()
        assert len(mapper.get_rules_for_class(3001)) > 0


# ==============================================================================
# TestMapEvent
# ==============================================================================

class TestMapEvent:

    def test_none_event_raises_type_error(self):
        with pytest.raises(TypeError):
            MitreMapper().map_event(None)

    def test_returns_list(self, ocsf_registry):
        event = _make(ocsf_registry)
        result = MitreMapper().map_event(event)
        assert isinstance(result, list)

    def test_no_matching_rules_returns_empty_list(self, ocsf_registry):
        # activity_id=99 and severity_id=6 should match no auth rules
        event = _make(ocsf_registry, class_uid=6003,
                      activity_id=99, severity_id=6)
        result = MitreMapper().map_event(event)
        assert result == []

    def test_t1078_matched_on_successful_auth(self, ocsf_registry):
        # activity_id=1 (success), severity_id=1 (informational)
        event = _make(ocsf_registry, class_uid=6003,
                      activity_id=1, severity_id=1)
        result = MitreMapper().map_event(event)
        assert "T1078" in result

    def test_t1110_matched_on_failed_auth(self, ocsf_registry):
        # activity_id=2 (failure), severity_id=3 (medium)
        event = _make(ocsf_registry, class_uid=6003,
                      activity_id=2, severity_id=3)
        result = MitreMapper().map_event(event)
        assert "T1110" in result

    def test_t1110_001_matched_on_ntlm_failure(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=6003, activity_id=2,
                      severity_id=1)
        event._fields["auth.protocol_name"] = "NTLM"
        result = MitreMapper().map_event(event)
        assert "T1110.001" in result

    def test_t1078_002_matched_on_domain_account(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=6003, activity_id=1,
                      severity_id=1)
        event._fields["actor.user.name"] = "DOMAIN\\alice"
        result = MitreMapper().map_event(event)
        assert "T1078.002" in result

    def test_t1059_matched_on_cmd_exe(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=4001)
        event._fields["actor.process.name"] = "cmd.exe"
        result = MitreMapper().map_event(event)
        assert "T1059" in result

    def test_t1059_001_matched_on_powershell(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=4001)
        event._fields["actor.process.name"] = "powershell.exe"
        result = MitreMapper().map_event(event)
        assert "T1059.001" in result

    def test_t1059_matches_both_cmd_and_powershell(self, ocsf_registry):
        # T1059 fires for powershell too (contains "powershell")
        event = _make(ocsf_registry, class_uid=4001)
        event._fields["actor.process.name"] = "powershell.exe"
        result = MitreMapper().map_event(event)
        assert "T1059" in result
        assert "T1059.001" in result

    def test_t1055_matched_on_svchost_with_child(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=4001)
        event._fields["actor.process.name"] = "svchost.exe"
        event._fields["process.name"] = "malware.exe"
        result = MitreMapper().map_event(event)
        assert "T1055" in result

    def test_t1055_not_matched_when_child_absent(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=4001)
        event._fields["actor.process.name"] = "svchost.exe"
        # process.name not set
        result = MitreMapper().map_event(event)
        assert "T1055" not in result

    def test_t1053_matched_on_schtasks(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=4001)
        event._fields["actor.process.name"] = "schtasks.exe"
        result = MitreMapper().map_event(event)
        assert "T1053" in result

    def test_t1071_matched_on_port_80(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["dst_endpoint.port"] = 80
        result = MitreMapper().map_event(event)
        assert "T1071" in result

    def test_t1071_matched_on_port_443(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["dst_endpoint.port"] = 443
        result = MitreMapper().map_event(event)
        assert "T1071" in result

    def test_t1048_matched_on_large_transfer(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["network.bytes_out"] = 50_000_000
        result = MitreMapper().map_event(event)
        assert "T1048" in result

    def test_t1048_not_matched_below_threshold(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["network.bytes_out"] = 100
        result = MitreMapper().map_event(event)
        assert "T1048" not in result

    def test_t1046_matched_on_zero_bytes(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["dst_endpoint.port"] = 22
        event._fields["network.bytes_out"] = 0
        result = MitreMapper().map_event(event)
        assert "T1046" in result

    def test_t1190_matched_on_http_500(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3002)
        event._fields["http.response.code"] = "500"
        result = MitreMapper().map_event(event)
        assert "T1190" in result

    def test_t1059_007_matched_on_script_tag(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3002)
        event._fields["http.request.url.path"] = "/search?q=<script>alert(1)</script>"
        result = MitreMapper().map_event(event)
        assert "T1059.007" in result

    def test_t1005_matched_on_system32_path(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=1001)
        event._fields["file.path"] = "C:\\Windows\\System32\\config\\SAM"
        result = MitreMapper().map_event(event)
        assert "T1005" in result

    def test_t1005_matched_on_etc_passwd(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=1001)
        event._fields["file.path"] = "/etc/passwd"
        result = MitreMapper().map_event(event)
        assert "T1005" in result

    def test_t1070_004_matched_on_delete_activity(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=1001, activity_id=4)
        result = MitreMapper().map_event(event)
        assert "T1070.004" in result

    def test_predicate_exception_skips_rule_does_not_raise(
        self, ocsf_registry
    ):
        # Inject a broken rule via a custom MitreMapper subclass
        mapper = MitreMapper()
        bad_rule = MappingRule(
            technique_id="T9999",
            class_uid=6003,
            description="Raises on eval",
            predicate=lambda e: 1 / 0,  # ZeroDivisionError
        )
        mapper._rules_by_class[6003].append(bad_rule)
        event = _make(ocsf_registry, class_uid=6003)
        result = mapper.map_event(event)
        # Bad rule skipped — T9999 not in result, no exception raised
        assert "T9999" not in result

    def test_class_with_no_rules_returns_empty_list(self, ocsf_registry):
        # 1001 has rules; inject empty to test empty path
        mapper = MitreMapper()
        mapper._rules_by_class[1001] = []
        event = _make(ocsf_registry, class_uid=1001)
        assert mapper.map_event(event) == []


# ==============================================================================
# TestGetCoverage
# ==============================================================================

class TestGetCoverage:

    def test_returns_dict(self):
        coverage = MitreMapper().get_coverage()
        assert isinstance(coverage, dict)

    def test_all_supported_classes_in_coverage(self):
        coverage = MitreMapper().get_coverage()
        assert set(coverage.keys()) == SUPPORTED_CLASSES

    def test_auth_class_coverage_non_empty(self):
        coverage = MitreMapper().get_coverage()
        assert len(coverage[6003]) > 0

    def test_values_are_sets_of_strings(self):
        coverage = MitreMapper().get_coverage()
        for uid, techniques in coverage.items():
            assert isinstance(techniques, set)
            assert all(isinstance(t, str) for t in techniques)

    def test_known_techniques_in_coverage(self):
        coverage = MitreMapper().get_coverage()
        assert "T1078" in coverage[6003]
        assert "T1059" in coverage[4001]
        assert "T1071" in coverage[3001]


# ==============================================================================
# TestGetRulesForClass
# ==============================================================================

class TestGetRulesForClass:

    def test_supported_class_with_rules_returns_list(self):
        rules = MitreMapper().get_rules_for_class(6003)
        assert isinstance(rules, list)
        assert len(rules) > 0

    def test_unsupported_class_returns_empty_list(self):
        rules = MitreMapper().get_rules_for_class(9999)
        assert rules == []

    def test_returns_mapping_rule_objects(self):
        rules = MitreMapper().get_rules_for_class(4001)
        assert all(isinstance(r, MappingRule) for r in rules)

    def test_return_is_copy(self):
        mapper = MitreMapper()
        rules = mapper.get_rules_for_class(6003)
        original_len = len(rules)
        rules.clear()
        assert len(mapper.get_rules_for_class(6003)) == original_len


# ==============================================================================
# TestHelperFunctions
# ==============================================================================

class TestHelperFunctions:

    def test_field_returns_value(self, ocsf_registry):
        event = _make(ocsf_registry)
        event._fields["actor.user.name"] = "alice"
        assert _field(event, "actor.user.name") == "alice"

    def test_field_returns_none_for_missing(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert _field(event, "actor.user.name") is None

    def test_field_returns_none_on_exception(self):
        assert _field(None, "any.field") is None

    def test_eq_match(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert _eq(event, "activity_id", 1) is True

    def test_eq_no_match(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert _eq(event, "activity_id", 99) is False

    def test_eq_none_value(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert _eq(event, "actor.user.name", None) is True

    def test_contains_match(self, ocsf_registry):
        event = _make(ocsf_registry)
        event._fields["actor.user.name"] = "DOMAIN\\alice"
        assert _contains(event, "actor.user.name", "\\") is True

    def test_contains_case_insensitive(self, ocsf_registry):
        event = _make(ocsf_registry)
        event._fields["actor.user.name"] = "PowerShell.exe"
        assert _contains(event, "actor.user.name", "powershell") is True

    def test_contains_no_match(self, ocsf_registry):
        event = _make(ocsf_registry)
        event._fields["actor.user.name"] = "alice"
        assert _contains(event, "actor.user.name", "bob") is False

    def test_contains_none_value_returns_false(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert _contains(event, "actor.user.name", "anything") is False

    def test_gt_above_threshold(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["network.bytes_out"] = 20_000_000
        assert _gt(event, "network.bytes_out", 10_000_000) is True

    def test_gt_below_threshold(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["network.bytes_out"] = 100
        assert _gt(event, "network.bytes_out", 10_000_000) is False

    def test_gt_none_value_returns_false(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        assert _gt(event, "network.bytes_out", 0) is False

    def test_gt_non_numeric_returns_false(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["network.bytes_out"] = "not_a_number"
        assert _gt(event, "network.bytes_out", 0) is False

    def test_not_none_set_field_returns_true(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=4001)
        event._fields["process.name"] = "malware.exe"
        assert _not_none(event, "process.name") is True

    def test_not_none_missing_field_returns_false(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=4001)
        assert _not_none(event, "process.name") is False


# ==============================================================================
# TestMappingRuleImmutability
# ==============================================================================

class TestMappingRuleImmutability:

    def test_mapping_rule_is_frozen(self):
        rule = MappingRule(
            technique_id="T9999",
            class_uid=6003,
            description="test",
            predicate=lambda e: True,
        )
        with pytest.raises((AttributeError, TypeError)):
            rule.technique_id = "T0000"


    def test_contains_exception_in_str_returns_false(self, ocsf_registry):
        # Force the except branch in _contains by using an object
        # whose __str__ raises
        class _BadStr:
            def __str__(self):
                raise RuntimeError("deliberate str error")

        event = _make(ocsf_registry)
        event._fields["actor.user.name"] = _BadStr()
        assert _contains(event, "actor.user.name", "anything") is False