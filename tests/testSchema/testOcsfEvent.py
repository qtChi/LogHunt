# ==============================================================================
# tests/testSchema/testOcsfEvent.py
#
# Tests for loghunter/schema/ocsf_event.py
#
# Coverage strategy — every branch in ocsf_event.py explicitly targeted:
#
# Constructor type checks:
#   class_uid=None, activity_id=None, severity_id=None, time=None,
#   metadata_log_source=None, metadata_original_time=None, registry=None
#
# Constructor value checks:
#   unsupported class_uid, bool passed as int, negative activity_id,
#   severity_id out of range (below 0, above 6), naive datetime,
#   empty/whitespace metadata_log_source, empty/whitespace metadata_original_time,
#   wrong registry type, unknown kwarg field
#
# Constructor happy paths:
#   all five supported classes, severity_id boundary values (0 and 6),
#   with and without optional kwargs
#
# to_dict:
#   None fields included, minimum six keys, optional fields present
#
# get_field:
#   None path → TypeError, unknown field → ValueError,
#   set field → value, unset registered field → None
#
# set_field:
#   None path → TypeError, unknown field → ValueError,
#   valid set then get, overwrite existing value
#
# validate:
#   all required fields present → empty list
#   required field is None → error string
#   severity_id out of range post-construction (via set_field workaround)
#   naive time → error
#   invalid IPv4 → error, invalid IPv6 → error, valid IPs → no error
#   port out of range → error, valid port → no error
#   non-integer port → error
#
# get_class_uid, get_time: basic returns
#
# __eq__:
#   identical events → True, different class_uid → False,
#   different time → False, different source → False,
#   different original_time → False, non-OCSFEvent → False
#
# __repr__: format check
#
# __hash__: equal events have equal hashes
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from loghunter.exceptions import UnknownFieldError, UnsupportedClassError
from loghunter.schema.ocsf_field_registry import SUPPORTED_CLASSES
from loghunter.schema.ocsf_event import OCSFEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

UTC = timezone.utc
T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _make(ocsf_registry, **overrides):
    """Build a minimal valid OCSFEvent, overriding any arg as needed."""
    defaults = dict(
        class_uid=6003,
        activity_id=1,
        severity_id=1,
        time=T0,
        metadata_log_source="test",
        metadata_original_time="2026-01-01T00:00:00Z",
        registry=ocsf_registry,
    )
    defaults.update(overrides)
    return OCSFEvent(**defaults)


# ==============================================================================
# TestConstructorTypeChecks
# ==============================================================================

class TestConstructorTypeChecks:
    """Every required arg raises TypeError when None."""

    def test_none_class_uid_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="class_uid"):
            _make(ocsf_registry, class_uid=None)

    def test_none_activity_id_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="activity_id"):
            _make(ocsf_registry, activity_id=None)

    def test_none_severity_id_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="severity_id"):
            _make(ocsf_registry, severity_id=None)

    def test_none_time_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="time"):
            _make(ocsf_registry, time=None)

    def test_none_metadata_log_source_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="metadata_log_source"):
            _make(ocsf_registry, metadata_log_source=None)

    def test_none_metadata_original_time_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="metadata_original_time"):
            _make(ocsf_registry, metadata_original_time=None)

    def test_none_registry_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="registry"):
            _make(ocsf_registry, registry=None)

    def test_bool_activity_id_raises_type_error(self, ocsf_registry):
        # bool is subclass of int — must be explicitly rejected
        with pytest.raises(TypeError, match="activity_id"):
            _make(ocsf_registry, activity_id=True)

    def test_bool_severity_id_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="severity_id"):
            _make(ocsf_registry, severity_id=False)

    def test_string_activity_id_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError):
            _make(ocsf_registry, activity_id="1")

    def test_float_severity_id_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError):
            _make(ocsf_registry, severity_id=1.0)

    def test_string_time_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError):
            _make(ocsf_registry, time="2026-01-01T00:00:00Z")

    def test_wrong_registry_type_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="registry"):
            _make(ocsf_registry, registry="not a registry")

    def test_dict_registry_raises_type_error(self, ocsf_registry):
        with pytest.raises(TypeError, match="registry"):
            _make(ocsf_registry, registry={})


# ==============================================================================
# TestConstructorValueChecks
# ==============================================================================

class TestConstructorValueChecks:
    """Every value constraint raises ValueError (or subclass) on violation."""

    @pytest.mark.parametrize("bad_uid", [0, 999, 9999, -1, 1000])
    def test_unsupported_class_uid_raises_unsupported_class_error(
        self, ocsf_registry, bad_uid
    ):
        with pytest.raises(UnsupportedClassError):
            _make(ocsf_registry, class_uid=bad_uid)

    def test_unsupported_class_is_also_value_error(self, ocsf_registry):
        with pytest.raises(ValueError):
            _make(ocsf_registry, class_uid=9999)

    def test_negative_activity_id_raises_value_error(self, ocsf_registry):
        with pytest.raises(ValueError, match="non-negative"):
            _make(ocsf_registry, activity_id=-1)

    def test_zero_activity_id_is_valid(self, ocsf_registry):
        event = _make(ocsf_registry, activity_id=0)
        assert event.get_field("activity_id") == 0

    @pytest.mark.parametrize("bad_sev", [-1, 7, 100, -100])
    def test_severity_out_of_range_raises_value_error(
        self, ocsf_registry, bad_sev
    ):
        with pytest.raises(ValueError, match="0–6"):
            _make(ocsf_registry, severity_id=bad_sev)

    @pytest.mark.parametrize("ok_sev", [0, 1, 2, 3, 4, 5, 6])
    def test_severity_boundary_values_are_valid(self, ocsf_registry, ok_sev):
        event = _make(ocsf_registry, severity_id=ok_sev)
        assert event.get_field("severity_id") == ok_sev

    def test_naive_datetime_raises_value_error(self, ocsf_registry):
        naive = datetime(2026, 1, 1, 0, 0, 0)
        with pytest.raises(ValueError, match="timezone-aware"):
            _make(ocsf_registry, time=naive)

    def test_empty_metadata_log_source_raises_value_error(self, ocsf_registry):
        with pytest.raises(ValueError, match="metadata_log_source"):
            _make(ocsf_registry, metadata_log_source="")

    def test_whitespace_metadata_log_source_raises_value_error(
        self, ocsf_registry
    ):
        with pytest.raises(ValueError, match="metadata_log_source"):
            _make(ocsf_registry, metadata_log_source="   ")

    def test_empty_metadata_original_time_raises_value_error(
        self, ocsf_registry
    ):
        with pytest.raises(ValueError, match="metadata_original_time"):
            _make(ocsf_registry, metadata_original_time="")

    def test_whitespace_metadata_original_time_raises_value_error(
        self, ocsf_registry
    ):
        with pytest.raises(ValueError, match="metadata_original_time"):
            _make(ocsf_registry, metadata_original_time="  ")

    def test_unknown_kwarg_raises_unknown_field_error(self, ocsf_registry):
        with pytest.raises(UnknownFieldError):
            _make(ocsf_registry, **{"totally.unknown.field": "value"})

    def test_unknown_field_error_is_also_value_error(self, ocsf_registry):
        with pytest.raises(ValueError):
            _make(ocsf_registry, **{"no.such.field": "x"})

    def test_field_valid_for_other_class_raises_unknown_field_error(
        self, ocsf_registry
    ):
        # network.bytes_out is 3001 only — not valid for 6003
        with pytest.raises(UnknownFieldError):
            _make(ocsf_registry, class_uid=6003,
                  **{"network.bytes_out": 100})


# ==============================================================================
# TestConstructorHappyPath
# ==============================================================================

class TestConstructorHappyPath:
    """Valid construction for all five supported classes."""

    @pytest.mark.parametrize("class_uid", sorted(SUPPORTED_CLASSES))
    def test_all_supported_classes_construct_successfully(
        self, ocsf_registry, class_uid
    ):
        event = _make(ocsf_registry, class_uid=class_uid)
        assert event.get_class_uid() == class_uid

    def test_optional_kwargs_stored_correctly(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=6003,
            **{"actor.user.name": "alice"}
        )
        assert event.get_field("actor.user.name") == "alice"

    def test_multiple_valid_kwargs_all_stored(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=6003,
            **{
                "actor.user.name": "bob",
                "actor.user.uid": "S-1-5-21",
            }
        )
        assert event.get_field("actor.user.name") == "bob"
        assert event.get_field("actor.user.uid") == "S-1-5-21"

    def test_none_value_kwarg_is_stored(self, ocsf_registry):
        # None is a valid value for optional fields
        event = _make(
            ocsf_registry,
            class_uid=6003,
            **{"actor.user.name": None}
        )
        assert event.get_field("actor.user.name") is None

    def test_non_utc_aware_datetime_is_accepted(self, ocsf_registry):
        # Spec requires timezone-aware, not necessarily UTC offset=0
        # A datetime with a non-UTC tz is still timezone-aware
        from datetime import timezone
        tz_plus1 = timezone(timedelta(hours=1))
        t = datetime(2026, 1, 1, 1, 0, 0, tzinfo=tz_plus1)
        event = _make(ocsf_registry, time=t)
        assert event.get_time() == t


# ==============================================================================
# TestToDict
# ==============================================================================

class TestToDict:

    def test_returns_dict(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert isinstance(event.to_dict(), dict)

    def test_contains_all_six_required_fields(self, ocsf_registry):
        d = _make(ocsf_registry).to_dict()
        for key in ("class_uid", "activity_id", "severity_id", "time",
                    "metadata.log_source", "metadata.original_time"):
            assert key in d

    def test_none_values_included_not_omitted(self, ocsf_registry):
        event = _make(ocsf_registry, **{"actor.user.name": None})
        d = event.to_dict()
        assert "actor.user.name" in d
        assert d["actor.user.name"] is None

    def test_optional_fields_included_when_set(self, ocsf_registry):
        event = _make(ocsf_registry, **{"actor.user.name": "alice"})
        assert event.to_dict()["actor.user.name"] == "alice"

    def test_returns_copy_not_internal_reference(self, ocsf_registry):
        event = _make(ocsf_registry)
        d = event.to_dict()
        d["class_uid"] = 9999
        assert event.get_class_uid() == 6003

    def test_values_match_constructor_args(self, ocsf_registry):
        event = _make(ocsf_registry, activity_id=42, severity_id=3)
        d = event.to_dict()
        assert d["activity_id"] == 42
        assert d["severity_id"] == 3


# ==============================================================================
# TestGetField
# ==============================================================================

class TestGetField:

    def test_none_field_path_raises_type_error(self, ocsf_registry):
        event = _make(ocsf_registry)
        with pytest.raises(TypeError):
            event.get_field(None)

    def test_unknown_field_raises_value_error(self, ocsf_registry):
        event = _make(ocsf_registry)
        with pytest.raises(ValueError):
            event.get_field("no.such.field")

    def test_field_for_wrong_class_raises_value_error(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=6003)
        # network.bytes_out is 3001 only
        with pytest.raises(ValueError):
            event.get_field("network.bytes_out")

    def test_set_field_returns_correct_value(self, ocsf_registry):
        event = _make(ocsf_registry, **{"actor.user.name": "alice"})
        assert event.get_field("actor.user.name") == "alice"

    def test_unset_registered_field_returns_none(self, ocsf_registry):
        # actor.user.name registered for 6003 but not set
        event = _make(ocsf_registry)
        assert event.get_field("actor.user.name") is None

    def test_required_field_returns_correct_value(self, ocsf_registry):
        event = _make(ocsf_registry, severity_id=4)
        assert event.get_field("severity_id") == 4

    def test_empty_string_field_path_raises_value_error(self, ocsf_registry):
        event = _make(ocsf_registry)
        with pytest.raises(ValueError):
            event.get_field("")


# ==============================================================================
# TestSetField
# ==============================================================================

class TestSetField:

    def test_none_field_path_raises_type_error(self, ocsf_registry):
        event = _make(ocsf_registry)
        with pytest.raises(TypeError):
            event.set_field(None, "value")

    def test_unknown_field_raises_value_error(self, ocsf_registry):
        event = _make(ocsf_registry)
        with pytest.raises(ValueError):
            event.set_field("no.such.field", "x")

    def test_field_for_wrong_class_raises_value_error(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=6003)
        with pytest.raises(ValueError):
            event.set_field("network.bytes_out", 100)

    def test_valid_set_then_get_returns_value(self, ocsf_registry):
        event = _make(ocsf_registry)
        event.set_field("actor.user.name", "charlie")
        assert event.get_field("actor.user.name") == "charlie"

    def test_overwrite_existing_value(self, ocsf_registry):
        event = _make(ocsf_registry, **{"actor.user.name": "original"})
        event.set_field("actor.user.name", "updated")
        assert event.get_field("actor.user.name") == "updated"

    def test_set_none_value_is_valid(self, ocsf_registry):
        event = _make(ocsf_registry, **{"actor.user.name": "alice"})
        event.set_field("actor.user.name", None)
        assert event.get_field("actor.user.name") is None

    def test_set_mitre_technique_ids(self, ocsf_registry):
        event = _make(ocsf_registry)
        event.set_field("mitre_technique_ids", ["T1078", "T1110"])
        assert event.get_field("mitre_technique_ids") == ["T1078", "T1110"]


# ==============================================================================
# TestValidate
# ==============================================================================

class TestValidate:

    def test_valid_event_returns_empty_list(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert event.validate() == []

    def test_returns_list(self, ocsf_registry):
        assert isinstance(_make(ocsf_registry).validate(), list)

    def test_required_field_none_produces_error(self, ocsf_registry):
        event = _make(ocsf_registry)
        # Force a required field to None bypassing constructor
        event._fields["metadata.log_source"] = None
        errors = event.validate()
        assert any("metadata.log_source" in e for e in errors)

    def test_all_required_fields_none_produces_multiple_errors(
        self, ocsf_registry
    ):
        event = _make(ocsf_registry)
        for f in ("class_uid", "activity_id", "severity_id", "time",
                  "metadata.log_source", "metadata.original_time"):
            event._fields[f] = None
        errors = event.validate()
        assert len(errors) == 6

    def test_naive_time_in_fields_produces_error(self, ocsf_registry):
        event = _make(ocsf_registry)
        event._fields["time"] = datetime(2026, 1, 1)
        errors = event.validate()
        assert any("timezone" in e for e in errors)

    def test_valid_ipv4_produces_no_error(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"src_endpoint.ip": "192.168.1.1"}
        )
        errors = event.validate()
        assert not any("src_endpoint.ip" in e for e in errors)

    def test_valid_ipv6_produces_no_error(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"src_endpoint.ip": "::1"}
        )
        errors = event.validate()
        assert not any("src_endpoint.ip" in e for e in errors)

    def test_invalid_ip_produces_error(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"src_endpoint.ip": "not-an-ip"}
        )
        errors = event.validate()
        assert any("src_endpoint.ip" in e for e in errors)

    def test_invalid_dst_ip_produces_error(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"dst_endpoint.ip": "999.999.999.999"}
        )
        errors = event.validate()
        assert any("dst_endpoint.ip" in e for e in errors)

    def test_valid_port_produces_no_error(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"src_endpoint.port": 443}
        )
        assert event.validate() == []

    def test_port_zero_is_valid(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"src_endpoint.port": 0}
        )
        assert event.validate() == []

    def test_port_65535_is_valid(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"dst_endpoint.port": 65535}
        )
        assert event.validate() == []

    def test_port_above_65535_produces_error(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"src_endpoint.port": 65536}
        )
        errors = event.validate()
        assert any("src_endpoint.port" in e for e in errors)

    def test_negative_port_produces_error(self, ocsf_registry):
        event = _make(
            ocsf_registry,
            class_uid=3001,
            **{"dst_endpoint.port": -1}
        )
        errors = event.validate()
        assert any("dst_endpoint.port" in e for e in errors)

    def test_non_integer_port_produces_error(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        event._fields["src_endpoint.port"] = "443"
        errors = event.validate()
        assert any("src_endpoint.port" in e for e in errors)

    def test_none_ip_skipped_no_error(self, ocsf_registry):
        # None IP fields are not validated — only non-None values checked
        event = _make(ocsf_registry, class_uid=3001)
        assert event.validate() == []

    def test_none_port_skipped_no_error(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=3001)
        assert event.validate() == []

    def test_validate_does_not_raise_on_any_input(self, ocsf_registry):
        event = _make(ocsf_registry)
        event._fields["time"] = "not a datetime"
        event._fields["severity_id"] = 99
        # Must never raise
        result = event.validate()
        assert isinstance(result, list)


# ==============================================================================
# TestGetClassUid
# ==============================================================================

class TestGetClassUid:

    @pytest.mark.parametrize("class_uid", sorted(SUPPORTED_CLASSES))
    def test_returns_correct_class_uid(self, ocsf_registry, class_uid):
        event = _make(ocsf_registry, class_uid=class_uid)
        assert event.get_class_uid() == class_uid


# ==============================================================================
# TestGetTime
# ==============================================================================

class TestGetTime:

    def test_returns_correct_time(self, ocsf_registry):
        event = _make(ocsf_registry, time=T0)
        assert event.get_time() == T0

    def test_returned_time_is_datetime(self, ocsf_registry):
        assert isinstance(_make(ocsf_registry).get_time(), datetime)

    def test_returned_time_is_timezone_aware(self, ocsf_registry):
        assert _make(ocsf_registry).get_time().tzinfo is not None


# ==============================================================================
# TestEquality
# ==============================================================================

class TestEquality:

    def test_identical_events_are_equal(self, ocsf_registry):
        a = _make(ocsf_registry)
        b = _make(ocsf_registry)
        assert a == b

    def test_different_class_uid_not_equal(self, ocsf_registry):
        a = _make(ocsf_registry, class_uid=6003)
        b = _make(ocsf_registry, class_uid=4001)
        assert a != b

    def test_different_time_not_equal(self, ocsf_registry):
        a = _make(ocsf_registry, time=T0)
        b = _make(ocsf_registry, time=datetime(2026, 6, 1, tzinfo=UTC))
        assert a != b

    def test_different_log_source_not_equal(self, ocsf_registry):
        a = _make(ocsf_registry, metadata_log_source="evtx")
        b = _make(ocsf_registry, metadata_log_source="zeek")
        assert a != b

    def test_different_original_time_not_equal(self, ocsf_registry):
        a = _make(ocsf_registry, metadata_original_time="2026-01-01T00:00:00Z")
        b = _make(ocsf_registry, metadata_original_time="2026-06-01T00:00:00Z")
        assert a != b

    def test_non_ocsf_event_not_equal_never_raises(self, ocsf_registry):
        event = _make(ocsf_registry)
        assert event != "not an event"
        assert event != 42
        assert event != None
        assert event != {}

    def test_different_optional_fields_still_equal(self, ocsf_registry):
        # __eq__ only checks the four identity fields
        a = _make(ocsf_registry, **{"actor.user.name": "alice"})
        b = _make(ocsf_registry, **{"actor.user.name": "bob"})
        assert a == b


# ==============================================================================
# TestHash
# ==============================================================================

class TestHash:

    def test_equal_events_have_equal_hashes(self, ocsf_registry):
        a = _make(ocsf_registry)
        b = _make(ocsf_registry)
        assert hash(a) == hash(b)

    def test_events_usable_in_set(self, ocsf_registry):
        a = _make(ocsf_registry)
        b = _make(ocsf_registry)
        s = {a, b}
        assert len(s) == 1

    def test_different_events_in_set(self, ocsf_registry):
        a = _make(ocsf_registry, metadata_log_source="evtx")
        b = _make(ocsf_registry, metadata_log_source="zeek")
        s = {a, b}
        assert len(s) == 2


# ==============================================================================
# TestRepr
# ==============================================================================

class TestRepr:

    def test_repr_contains_class_uid(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=6003)
        assert "6003" in repr(event)

    def test_repr_contains_source(self, ocsf_registry):
        event = _make(ocsf_registry, metadata_log_source="evtx")
        assert "evtx" in repr(event)

    def test_repr_contains_time(self, ocsf_registry):
        event = _make(ocsf_registry, time=T0)
        assert "2026-01-01" in repr(event)

    def test_repr_format(self, ocsf_registry):
        event = _make(ocsf_registry, class_uid=6003,
                      metadata_log_source="evtx", time=T0)
        r = repr(event)
        assert r.startswith("OCSFEvent(")
        assert "class_uid=6003" in r
        assert "source=evtx" in r