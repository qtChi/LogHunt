# ==============================================================================
# tests/testSchema/testQueryIntent.py
#
# 100% branch coverage for loghunter/schema/query_intent.py
#
# Test strategy:
#   - Input space partitioning on every parameter boundary.
#   - Every __post_init__ guard: None, empty/whitespace, out-of-range.
#   - is_valid(): True (class_uid set) and False (class_uid None).
#   - to_builder_args(): valid + invalid + time_range present/absent +
#     filters present/empty.
#   - pytest.raises always asserts on the specific exception subclass.
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from loghunter.schema.query_intent import (
    VALID_OPERATORS,
    FilterIntent,
    QueryIntent,
)


# ===========================================================================
# FilterIntent
# ===========================================================================

class TestFilterIntentConstruction:
    """Happy-path construction and attribute storage."""

    def test_eq_operator_with_string_value(self):
        f = FilterIntent(field_path="actor.user.name", operator="eq", value="jsmith")
        assert f.field_path == "actor.user.name"
        assert f.operator == "eq"
        assert f.value == "jsmith"

    def test_gt_operator_with_int_value(self):
        f = FilterIntent(field_path="src_endpoint.port", operator="gt", value=1024)
        assert f.value == 1024

    def test_lte_operator_with_float_value(self):
        f = FilterIntent(field_path="network.bytes_out", operator="lte", value=9.5)
        assert f.value == 9.5

    def test_is_null_operator_value_defaults_none(self):
        f = FilterIntent(field_path="actor.user.name", operator="is_null")
        assert f.value is None

    def test_not_null_operator_value_none(self):
        f = FilterIntent(field_path="dst_endpoint.ip", operator="not_null", value=None)
        assert f.value is None

    def test_contains_operator(self):
        f = FilterIntent(field_path="http.request.url.path", operator="contains", value="/admin")
        assert f.operator == "contains"

    def test_ne_operator(self):
        f = FilterIntent(field_path="severity_id", operator="ne", value=1)
        assert f.operator == "ne"

    def test_lt_operator(self):
        f = FilterIntent(field_path="severity_id", operator="lt", value=5)
        assert f.operator == "lt"

    def test_gte_operator(self):
        f = FilterIntent(field_path="severity_id", operator="gte", value=3)
        assert f.operator == "gte"

    def test_all_valid_operators_accepted(self):
        """Every operator in VALID_OPERATORS must construct without error."""
        for op in VALID_OPERATORS:
            fi = FilterIntent(field_path="class_uid", operator=op)
            assert fi.operator == op


class TestFilterIntentFieldPathValidation:
    """field_path None → TypeError; empty/whitespace → ValueError."""

    def test_field_path_none_raises_type_error(self):
        with pytest.raises(TypeError, match="field_path must not be None"):
            FilterIntent(field_path=None, operator="eq")

    def test_field_path_empty_string_raises_value_error(self):
        with pytest.raises(ValueError, match="field_path must not be empty"):
            FilterIntent(field_path="", operator="eq")

    def test_field_path_whitespace_only_raises_value_error(self):
        with pytest.raises(ValueError, match="field_path must not be empty"):
            FilterIntent(field_path="   ", operator="eq")

    def test_field_path_single_space_raises_value_error(self):
        with pytest.raises(ValueError):
            FilterIntent(field_path=" ", operator="eq")


class TestFilterIntentOperatorValidation:
    """Unknown operator → ValueError naming the bad value."""

    def test_unknown_operator_raises_value_error(self):
        with pytest.raises(ValueError, match="not valid"):
            FilterIntent(field_path="actor.user.name", operator="LIKE")

    def test_empty_operator_raises_value_error(self):
        with pytest.raises(ValueError):
            FilterIntent(field_path="actor.user.name", operator="")

    def test_whitespace_operator_raises_value_error(self):
        with pytest.raises(ValueError):
            FilterIntent(field_path="actor.user.name", operator="  ")

    def test_capitalised_operator_raises_value_error(self):
        """Operators are case-sensitive — 'EQ' is not 'eq'."""
        with pytest.raises(ValueError):
            FilterIntent(field_path="actor.user.name", operator="EQ")

    def test_operator_with_leading_space_raises_value_error(self):
        with pytest.raises(ValueError):
            FilterIntent(field_path="actor.user.name", operator=" eq")


# ===========================================================================
# QueryIntent — construction
# ===========================================================================

class TestQueryIntentConstruction:
    """Happy-path construction and default values."""

    def test_minimal_construction_with_natural_language_only(self):
        qi = QueryIntent(natural_language="show me failed logins")
        assert qi.natural_language == "show me failed logins"
        assert qi.class_uid is None
        assert qi.filters == []
        assert qi.time_range_hours is None
        assert qi.confidence is None

    def test_full_construction(self):
        f = FilterIntent(field_path="severity_id", operator="gte", value=3)
        qi = QueryIntent(
            natural_language="high severity events",
            class_uid=6003,
            filters=[f],
            time_range_hours=24,
            confidence=0.87,
        )
        assert qi.class_uid == 6003
        assert len(qi.filters) == 1
        assert qi.time_range_hours == 24
        assert qi.confidence == 0.87

    def test_confidence_exactly_zero(self):
        qi = QueryIntent(natural_language="test", confidence=0.0)
        assert qi.confidence == 0.0

    def test_confidence_exactly_one(self):
        qi = QueryIntent(natural_language="test", confidence=1.0)
        assert qi.confidence == 1.0

    def test_confidence_midpoint(self):
        qi = QueryIntent(natural_language="test", confidence=0.5)
        assert qi.confidence == 0.5

    def test_time_range_hours_exactly_one(self):
        qi = QueryIntent(natural_language="test", time_range_hours=1)
        assert qi.time_range_hours == 1

    def test_time_range_hours_large_value(self):
        qi = QueryIntent(natural_language="test", time_range_hours=8760)
        assert qi.time_range_hours == 8760

    def test_empty_filters_list_stored(self):
        qi = QueryIntent(natural_language="test", filters=[])
        assert qi.filters == []

    def test_multiple_filters_stored(self):
        f1 = FilterIntent(field_path="severity_id", operator="gte", value=3)
        f2 = FilterIntent(field_path="actor.user.name", operator="eq", value="admin")
        qi = QueryIntent(natural_language="test", filters=[f1, f2])
        assert len(qi.filters) == 2


class TestQueryIntentNaturalLanguageValidation:
    """natural_language None → TypeError; empty/whitespace → ValueError."""

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError, match="natural_language must not be None"):
            QueryIntent(natural_language=None)

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError, match="natural_language must not be empty"):
            QueryIntent(natural_language="")

    def test_whitespace_only_raises_value_error(self):
        with pytest.raises(ValueError, match="natural_language must not be empty"):
            QueryIntent(natural_language="   ")

    def test_tab_only_raises_value_error(self):
        with pytest.raises(ValueError):
            QueryIntent(natural_language="\t")

    def test_newline_only_raises_value_error(self):
        with pytest.raises(ValueError):
            QueryIntent(natural_language="\n")


class TestQueryIntentConfidenceValidation:
    """confidence outside 0.0–1.0 → ValueError."""

    def test_confidence_above_one_raises_value_error(self):
        with pytest.raises(ValueError, match="confidence must be in range"):
            QueryIntent(natural_language="test", confidence=1.01)

    def test_confidence_below_zero_raises_value_error(self):
        with pytest.raises(ValueError, match="confidence must be in range"):
            QueryIntent(natural_language="test", confidence=-0.01)

    def test_confidence_negative_large_raises_value_error(self):
        with pytest.raises(ValueError):
            QueryIntent(natural_language="test", confidence=-1.0)

    def test_confidence_none_is_valid(self):
        """None confidence must not raise."""
        qi = QueryIntent(natural_language="test", confidence=None)
        assert qi.confidence is None


class TestQueryIntentTimeRangeValidation:
    """time_range_hours < 1 → ValueError."""

    def test_time_range_zero_raises_value_error(self):
        with pytest.raises(ValueError, match="time_range_hours must be >= 1"):
            QueryIntent(natural_language="test", time_range_hours=0)

    def test_time_range_negative_raises_value_error(self):
        with pytest.raises(ValueError, match="time_range_hours must be >= 1"):
            QueryIntent(natural_language="test", time_range_hours=-1)

    def test_time_range_large_negative_raises_value_error(self):
        with pytest.raises(ValueError):
            QueryIntent(natural_language="test", time_range_hours=-100)

    def test_time_range_none_is_valid(self):
        qi = QueryIntent(natural_language="test", time_range_hours=None)
        assert qi.time_range_hours is None


# ===========================================================================
# QueryIntent.is_valid()
# ===========================================================================

class TestQueryIntentIsValid:
    """is_valid() returns True iff class_uid is not None. Never raises."""

    def test_is_valid_true_when_class_uid_set(self):
        qi = QueryIntent(natural_language="test", class_uid=6003)
        assert qi.is_valid() is True

    def test_is_valid_false_when_class_uid_none(self):
        qi = QueryIntent(natural_language="test", class_uid=None)
        assert qi.is_valid() is False

    def test_is_valid_false_by_default(self):
        qi = QueryIntent(natural_language="test")
        assert qi.is_valid() is False

    def test_is_valid_all_supported_classes(self):
        for uid in (1001, 3001, 3002, 4001, 6003):
            qi = QueryIntent(natural_language="test", class_uid=uid)
            assert qi.is_valid() is True


# ===========================================================================
# QueryIntent.to_builder_args()
# ===========================================================================

class TestQueryIntentToBuilderArgs:
    """to_builder_args() converts intent to QueryBuilder kwargs."""

    def test_raises_value_error_when_not_valid(self):
        qi = QueryIntent(natural_language="no class")
        with pytest.raises(ValueError, match="QueryIntent is not valid"):
            qi.to_builder_args()

    def test_class_uid_in_output(self):
        qi = QueryIntent(natural_language="test", class_uid=3001)
        args = qi.to_builder_args()
        assert args["class_uid"] == 3001

    def test_empty_filters_returns_empty_dict(self):
        qi = QueryIntent(natural_language="test", class_uid=3001)
        args = qi.to_builder_args()
        assert args["filters"] == {}

    def test_filters_mapped_as_field_path_to_value(self):
        f1 = FilterIntent(field_path="severity_id", operator="gte", value=3)
        f2 = FilterIntent(field_path="actor.user.name", operator="eq", value="admin")
        qi = QueryIntent(natural_language="test", class_uid=6003, filters=[f1, f2])
        args = qi.to_builder_args()
        assert args["filters"] == {"severity_id": 3, "actor.user.name": "admin"}

    def test_time_range_none_when_not_set(self):
        qi = QueryIntent(natural_language="test", class_uid=6003)
        args = qi.to_builder_args()
        assert args["time_range"] is None

    def test_time_range_tuple_when_set(self):
        qi = QueryIntent(natural_language="test", class_uid=6003, time_range_hours=24)
        before = datetime.now(timezone.utc)
        args = qi.to_builder_args()
        after = datetime.now(timezone.utc)

        start, end = args["time_range"]
        assert isinstance(start, datetime)
        assert isinstance(end, datetime)
        assert start.tzinfo is not None
        assert end.tzinfo is not None
        # end should be "now" — within the test window
        assert before <= end <= after
        # start should be 24 hours before end
        delta = end - start
        assert 23 * 3600 < delta.total_seconds() <= 24 * 3600 + 1

    def test_time_range_one_hour(self):
        qi = QueryIntent(natural_language="test", class_uid=6003, time_range_hours=1)
        args = qi.to_builder_args()
        start, end = args["time_range"]
        delta = end - start
        assert 3599 < delta.total_seconds() <= 3601

    def test_time_range_large_window(self):
        qi = QueryIntent(natural_language="test", class_uid=6003, time_range_hours=720)
        args = qi.to_builder_args()
        start, end = args["time_range"]
        delta = end - start
        # 720 hours = 30 days
        assert delta.total_seconds() > 719 * 3600

    def test_filter_with_none_value_preserved(self):
        """is_null filter has value=None — must be preserved in output dict."""
        f = FilterIntent(field_path="actor.user.name", operator="is_null")
        qi = QueryIntent(natural_language="test", class_uid=6003, filters=[f])
        args = qi.to_builder_args()
        assert "actor.user.name" in args["filters"]
        assert args["filters"]["actor.user.name"] is None

    def test_all_keys_present_in_output(self):
        qi = QueryIntent(natural_language="test", class_uid=6003)
        args = qi.to_builder_args()
        assert set(args.keys()) == {"class_uid", "filters", "time_range"}


# ===========================================================================
# VALID_OPERATORS constant
# ===========================================================================

class TestValidOperatorsConstant:
    """Sanity-check the exported constant."""

    def test_is_frozenset(self):
        assert isinstance(VALID_OPERATORS, frozenset)

    def test_contains_all_nine_operators(self):
        expected = {"eq", "ne", "gt", "lt", "gte", "lte", "contains", "is_null", "not_null"}
        assert VALID_OPERATORS == expected

    def test_immutable(self):
        with pytest.raises(AttributeError):
            VALID_OPERATORS.add("like")