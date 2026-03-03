# ==============================================================================
# tests/testSchema/testOcsfFieldRegistry.py
#
# Tests for loghunter/schema/ocsf_field_registry.py
#
# Coverage strategy:
#   Every branch in ocsf_field_registry.py is explicitly targeted.
#   Input space partitions are derived from each method's parameter space.
#   All partition boundaries are tested including None, empty, invalid types.
#
# Branch map (line → test class that covers it):
#   L76  schema_path is None              → TestConstructorInvalidInputs
#   L80  path does not exist              → TestConstructorInvalidInputs
#   L87  JSONDecodeError                  → TestConstructorInvalidInputs
#   L92  "fields" not in raw              → TestConstructorInvalidInputs
#   L92  "fields" not a list              → TestConstructorInvalidInputs
#   L110 duplicate field_path (merge)     → TestConstructorDuplicateFields
#   L110 no duplicate (normal add)        → TestConstructorValidSchema
#   L129 class_uid in _by_class           → TestConstructorValidSchema
#   L129 class_uid NOT in _by_class       → TestConstructorUnsupportedInSchema
#   L134 field_path not in existing       → TestConstructorDuplicateFields
#   L136 field_path already in existing   → TestConstructorDuplicateFields
#   L154 missing required keys            → TestConstructorInvalidInputs
#   L204 unsupported class_uid            → TestGetFieldsForClass
#   L243 unsupported class (is_valid)     → TestIsValidField
#   L246 fd is None (is_valid)            → TestIsValidField
#   L248 class_uid not in applicable      → TestIsValidField
#   L264 fd is None (get_field_type)      → TestGetFieldType
#   L264 fd is not None (get_field_type)  → TestGetFieldType
# ==============================================================================

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loghunter.exceptions import UnsupportedClassError
from loghunter.schema.ocsf_field_registry import (
    SUPPORTED_CLASSES,
    FieldDefinition,
    OCSFFieldRegistry,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"
SCHEMA_PATH = str(CONFIG_DIR / "ocsf_schema.json")

UNIVERSAL_REQUIRED_FIELDS = {
    "class_uid",
    "activity_id",
    "severity_id",
    "time",
    "metadata.log_source",
    "metadata.original_time",
}

# ---------------------------------------------------------------------------
# Minimal valid schema factory for isolated constructor tests
# ---------------------------------------------------------------------------

def _minimal_schema(fields: list[dict]) -> dict:
    return {"version": "1.0.0", "fields": fields}


def _write_schema(tmp_path, data: dict) -> str:
    p = tmp_path / "schema.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _universal_field(
    field_path: str = "class_uid",
    field_type: str = "INTEGER",
    required: bool = True,
    applicable_classes: list[int] | None = None,
) -> dict:
    return {
        "field_path": field_path,
        "field_type": field_type,
        "required": required,
        "applicable_classes": applicable_classes or [1001, 3001, 3002, 4001, 6003],
        "description": f"Test field {field_path}",
        "source_examples": [],
    }


# ==============================================================================
# TestConstructorValidSchema
# ==============================================================================

class TestConstructorValidSchema:
    """Partition: valid schema file — happy path branches."""

    def test_loads_real_schema_without_error(self):
        registry = OCSFFieldRegistry(SCHEMA_PATH)
        assert registry is not None

    def test_schema_version_populated(self):
        registry = OCSFFieldRegistry(SCHEMA_PATH)
        assert isinstance(registry.schema_version, str)
        assert len(registry.schema_version) > 0

    def test_schema_version_matches_file(self):
        raw = json.loads(Path(SCHEMA_PATH).read_text(encoding="utf-8"))
        registry = OCSFFieldRegistry(SCHEMA_PATH)
        assert registry.schema_version == raw.get("version", "unknown")

    def test_empty_fields_list_is_valid(self, tmp_path):
        # Branch: fields list present but empty — no iteration, no error
        path = _write_schema(tmp_path, _minimal_schema([]))
        registry = OCSFFieldRegistry(path)
        assert registry is not None

    def test_field_without_optional_keys_uses_defaults(self, tmp_path):
        # description and source_examples are optional
        field = {
            "field_path": "class_uid",
            "field_type": "INTEGER",
            "required": True,
            "applicable_classes": [6003],
        }
        path = _write_schema(tmp_path, _minimal_schema([field]))
        registry = OCSFFieldRegistry(path)
        fd = registry.get_field_definition("class_uid")
        assert fd.description == ""
        assert fd.source_examples == ()

    def test_applicable_class_not_in_supported_set_is_skipped(self, tmp_path):
        # Branch L129: class_uid NOT in _by_class — field has unsupported class
        # The field should load but not appear in any class list
        field = _universal_field(applicable_classes=[9999])
        path = _write_schema(tmp_path, _minimal_schema([field]))
        registry = OCSFFieldRegistry(path)
        # Field is still findable by path
        fd = registry.get_field_definition("class_uid")
        assert fd is not None
        # But it is not in any supported class list
        for uid in SUPPORTED_CLASSES:
            paths = {f.field_path for f in registry.get_fields_for_class(uid)}
            assert "class_uid" not in paths

    def test_all_five_supported_classes_indexed(self):
        registry = OCSFFieldRegistry(SCHEMA_PATH)
        for uid in SUPPORTED_CLASSES:
            fields = registry.get_fields_for_class(uid)
            assert len(fields) > 0


# ==============================================================================
# TestConstructorInvalidInputs
# ==============================================================================

class TestConstructorInvalidInputs:
    """Partition: invalid constructor arguments — all error branches."""

    def test_none_raises_type_error(self):
        # Branch L76
        with pytest.raises(TypeError):
            OCSFFieldRegistry(None)

    def test_nonexistent_path_raises_file_not_found(self):
        # Branch L80
        with pytest.raises(FileNotFoundError):
            OCSFFieldRegistry("/no/such/file.json")

    def test_empty_string_path_raises_value_error(self, tmp_path):
        # Per spec D-001: empty string treated same as None → ValueError
        with pytest.raises(ValueError):
            OCSFFieldRegistry("")

    def test_invalid_json_raises_value_error(self, tmp_path):
        # Branch L87
        p = tmp_path / "bad.json"
        p.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            OCSFFieldRegistry(str(p))

    def test_json_missing_fields_key_raises_value_error(self, tmp_path):
        # Branch L92 — "fields" not in raw
        p = tmp_path / "no_fields.json"
        p.write_text(json.dumps({"version": "1.0.0"}), encoding="utf-8")
        with pytest.raises(ValueError, match="'fields'"):
            OCSFFieldRegistry(str(p))

    def test_fields_as_dict_not_list_raises_value_error(self, tmp_path):
        # Branch L92 — isinstance check fails
        p = tmp_path / "bad_fields.json"
        p.write_text(json.dumps({"fields": {}}), encoding="utf-8")
        with pytest.raises(ValueError, match="'fields'"):
            OCSFFieldRegistry(str(p))

    def test_fields_as_string_raises_value_error(self, tmp_path):
        # Branch L92 — isinstance check fails, different type
        p = tmp_path / "bad_fields2.json"
        p.write_text(json.dumps({"fields": "not a list"}), encoding="utf-8")
        with pytest.raises(ValueError, match="'fields'"):
            OCSFFieldRegistry(str(p))

    @pytest.mark.parametrize("missing_key", [
        "field_path",
        "field_type",
        "required",
        "applicable_classes",
    ])
    def test_field_missing_required_key_raises_value_error(
        self, tmp_path, missing_key
    ):
        # Branch L154 — each required key tested individually
        field = _universal_field()
        del field[missing_key]
        path = _write_schema(tmp_path, _minimal_schema([field]))
        with pytest.raises(ValueError):
            OCSFFieldRegistry(path)


# ==============================================================================
# TestConstructorDuplicateFields
# ==============================================================================

class TestConstructorDuplicateFields:
    """
    Partition: duplicate field_path entries in schema JSON.
    Covers the merge branch (L110) and both sub-branches (L134, L136).
    """

    def test_duplicate_field_merges_applicable_classes(self, tmp_path):
        # Branch L110 (duplicate), L134 (not yet in class list)
        fields = [
            _universal_field("src_endpoint.ip", "VARCHAR",
                             False, [3001, 3002]),
            _universal_field("src_endpoint.ip", "VARCHAR",
                             False, [6003]),
        ]
        path = _write_schema(tmp_path, _minimal_schema(fields))
        registry = OCSFFieldRegistry(path)
        fd = registry.get_field_definition("src_endpoint.ip")
        assert set(fd.applicable_classes) == {3001, 3002, 6003}

    def test_duplicate_field_required_true_wins(self, tmp_path):
        # Merge: one entry required=False, other required=True → True wins
        fields = [
            _universal_field("class_uid", "INTEGER", False, [6003]),
            _universal_field("class_uid", "INTEGER", True,  [6003]),
        ]
        path = _write_schema(tmp_path, _minimal_schema(fields))
        registry = OCSFFieldRegistry(path)
        fd = registry.get_field_definition("class_uid")
        assert fd.required is True

    def test_duplicate_field_required_false_does_not_override_true(
        self, tmp_path
    ):
        # Merge: required=True first, then False — True must be preserved
        fields = [
            _universal_field("class_uid", "INTEGER", True,  [6003]),
            _universal_field("class_uid", "INTEGER", False, [6003]),
        ]
        path = _write_schema(tmp_path, _minimal_schema(fields))
        registry = OCSFFieldRegistry(path)
        fd = registry.get_field_definition("class_uid")
        assert fd.required is True

    def test_duplicate_source_examples_are_deduplicated(self, tmp_path):
        # Merge: same example in both entries should not duplicate
        f1 = _universal_field("class_uid", applicable_classes=[6003])
        f1["source_examples"] = ["class_uid"]
        f2 = _universal_field("class_uid", applicable_classes=[4001])
        f2["source_examples"] = ["class_uid"]
        path = _write_schema(tmp_path, _minimal_schema([f1, f2]))
        registry = OCSFFieldRegistry(path)
        fd = registry.get_field_definition("class_uid")
        assert fd.source_examples.count("class_uid") == 1

    def test_duplicate_field_replaces_entry_in_class_list(self, tmp_path):
        # Branch L136: field_path already in class list → replace with merged
        fields = [
            _universal_field("class_uid", "INTEGER", False, [6003]),
            _universal_field("class_uid", "INTEGER", True,  [6003]),
        ]
        path = _write_schema(tmp_path, _minimal_schema(fields))
        registry = OCSFFieldRegistry(path)
        class_fields = registry.get_fields_for_class(6003)
        # Must appear exactly once
        matching = [f for f in class_fields if f.field_path == "class_uid"]
        assert len(matching) == 1

    def test_three_way_duplicate_merges_all_classes(self, tmp_path):
        # Stress test: three separate entries for same field_path
        fields = [
            _universal_field("time", "TIMESTAMP", True, [1001]),
            _universal_field("time", "TIMESTAMP", True, [3001]),
            _universal_field("time", "TIMESTAMP", True, [6003]),
        ]
        path = _write_schema(tmp_path, _minimal_schema(fields))
        registry = OCSFFieldRegistry(path)
        fd = registry.get_field_definition("time")
        assert set(fd.applicable_classes) == {1001, 3001, 6003}


# ==============================================================================
# TestGetFieldDefinition
# ==============================================================================

class TestGetFieldDefinition:
    """
    Input partitions:
      - Exact known field path  → FieldDefinition
      - Unknown path            → None
      - Empty string            → None
      - None                    → None (no raise)
      - Partial path segment    → None
      - Case-sensitive mismatch → None
    """

    def test_known_field_returns_field_definition(self, ocsf_registry):
        fd = ocsf_registry.get_field_definition("class_uid")
        assert isinstance(fd, FieldDefinition)
        assert fd.field_path == "class_uid"

    def test_nested_known_field_returns_field_definition(self, ocsf_registry):
        fd = ocsf_registry.get_field_definition("actor.user.name")
        assert fd is not None
        assert fd.field_path == "actor.user.name"

    def test_unknown_field_returns_none(self, ocsf_registry):
        assert ocsf_registry.get_field_definition("totally.unknown") is None

    def test_empty_string_returns_none(self, ocsf_registry):
        assert ocsf_registry.get_field_definition("") is None

    def test_none_returns_none_does_not_raise(self, ocsf_registry):
        # dict.get(None) is valid Python — must return None not raise
        result = ocsf_registry.get_field_definition(None)
        assert result is None

    def test_partial_path_returns_none(self, ocsf_registry):
        # "actor" alone is not a registered field
        assert ocsf_registry.get_field_definition("actor") is None

    def test_case_sensitive_mismatch_returns_none(self, ocsf_registry):
        assert ocsf_registry.get_field_definition("Class_UID") is None
        assert ocsf_registry.get_field_definition("CLASS_UID") is None

    def test_returned_field_definition_has_correct_attributes(
        self, ocsf_registry
    ):
        fd = ocsf_registry.get_field_definition("severity_id")
        assert isinstance(fd.field_path, str)
        assert isinstance(fd.field_type, str)
        assert isinstance(fd.required, bool)
        assert isinstance(fd.applicable_classes, tuple)
        assert isinstance(fd.description, str)
        assert isinstance(fd.source_examples, tuple)


# ==============================================================================
# TestGetFieldsForClass
# ==============================================================================

class TestGetFieldsForClass:
    """
    Input partitions:
      - Each of the five supported class_uids → non-empty list
      - Unsupported class_uid (various)       → UnsupportedClassError
      - Universal fields in every class       → all six present
      - Class-specific fields isolated        → not leaked to wrong class
    """

    @pytest.mark.parametrize("class_uid", sorted(SUPPORTED_CLASSES))
    def test_supported_class_returns_non_empty_list(
        self, ocsf_registry, class_uid
    ):
        fields = ocsf_registry.get_fields_for_class(class_uid)
        assert isinstance(fields, list)
        assert len(fields) > 0

    @pytest.mark.parametrize("class_uid", sorted(SUPPORTED_CLASSES))
    def test_all_six_universal_fields_in_every_class(
        self, ocsf_registry, class_uid
    ):
        paths = {fd.field_path for fd in ocsf_registry.get_fields_for_class(class_uid)}
        missing = UNIVERSAL_REQUIRED_FIELDS - paths
        assert not missing, (
            f"Class {class_uid} missing universal fields: {missing}"
        )

    @pytest.mark.parametrize("class_uid", sorted(SUPPORTED_CLASSES))
    def test_returns_list_of_field_definition_objects(
        self, ocsf_registry, class_uid
    ):
        fields = ocsf_registry.get_fields_for_class(class_uid)
        assert all(isinstance(f, FieldDefinition) for f in fields)

    @pytest.mark.parametrize("bad_uid", [0, -1, 9999, 1000, 99999])
    def test_unsupported_class_raises_unsupported_class_error(
        self, ocsf_registry, bad_uid
    ):
        with pytest.raises(UnsupportedClassError):
            ocsf_registry.get_fields_for_class(bad_uid)

    def test_unsupported_class_error_is_also_value_error(self, ocsf_registry):
        # UnsupportedClassError subclasses ValueError — broad catches still work
        with pytest.raises(ValueError):
            ocsf_registry.get_fields_for_class(9999)

    def test_auth_class_specific_fields_not_in_network_class(
        self, ocsf_registry
    ):
        # actor.user.name applies to 4001 and 6003, not 3001
        net_paths = {
            fd.field_path
            for fd in ocsf_registry.get_fields_for_class(3001)
        }
        assert "actor.user.name" not in net_paths

    def test_network_fields_not_in_auth_class(self, ocsf_registry):
        # network.bytes_out applies to 3001, not 6003
        auth_paths = {
            fd.field_path
            for fd in ocsf_registry.get_fields_for_class(6003)
        }
        assert "network.bytes_out" not in auth_paths

    def test_process_fields_not_in_file_class(self, ocsf_registry):
        # actor.process.name applies to 4001, not 1001
        file_paths = {
            fd.field_path
            for fd in ocsf_registry.get_fields_for_class(1001)
        }
        assert "actor.process.name" not in file_paths

    def test_return_is_a_copy_not_internal_reference(self, ocsf_registry):
        # Mutating the returned list must not affect the registry
        fields = ocsf_registry.get_fields_for_class(6003)
        original_len = len(fields)
        fields.clear()
        assert len(ocsf_registry.get_fields_for_class(6003)) == original_len


# ==============================================================================
# TestGetRequiredFields
# ==============================================================================

class TestGetRequiredFields:
    """
    Input partitions:
      - Supported class   → list containing at least the six universal fields
      - Unsupported class → UnsupportedClassError (delegated)
    """

    @pytest.mark.parametrize("class_uid", sorted(SUPPORTED_CLASSES))
    def test_required_fields_contains_all_universal_fields(
        self, ocsf_registry, class_uid
    ):
        required = set(ocsf_registry.get_required_fields(class_uid))
        missing = UNIVERSAL_REQUIRED_FIELDS - required
        assert not missing, (
            f"Class {class_uid} required fields missing: {missing}"
        )

    @pytest.mark.parametrize("class_uid", sorted(SUPPORTED_CLASSES))
    def test_returns_list_of_strings(self, ocsf_registry, class_uid):
        required = ocsf_registry.get_required_fields(class_uid)
        assert isinstance(required, list)
        assert all(isinstance(r, str) for r in required)

    def test_unsupported_class_raises_unsupported_class_error(
        self, ocsf_registry
    ):
        with pytest.raises(UnsupportedClassError):
            ocsf_registry.get_required_fields(9999)

    def test_optional_fields_not_in_required_list(self, ocsf_registry):
        # actor.user.name is optional — must not appear in required list
        required = ocsf_registry.get_required_fields(6003)
        assert "actor.user.name" not in required

    def test_required_fields_are_subset_of_all_fields(self, ocsf_registry):
        all_paths = {
            fd.field_path
            for fd in ocsf_registry.get_fields_for_class(6003)
        }
        required = set(ocsf_registry.get_required_fields(6003))
        assert required.issubset(all_paths)


# ==============================================================================
# TestIsValidField
# ==============================================================================

class TestIsValidField:
    """
    Input partitions — four distinct code paths through is_valid_field:
      Path A: class_uid not in SUPPORTED_CLASSES    → False  (L243)
      Path B: field_path not in _by_path (fd=None)  → False  (L246)
      Path C: fd exists, class not in applicable    → False  (L248)
      Path D: fd exists, class in applicable        → True   (L248)

    Additionally: None inputs — must never raise.
    """

    # Path D — True
    def test_valid_field_correct_class_returns_true(self, ocsf_registry):
        assert ocsf_registry.is_valid_field("actor.user.name", 6003) is True

    def test_universal_field_valid_for_all_supported_classes(
        self, ocsf_registry
    ):
        for uid in SUPPORTED_CLASSES:
            assert ocsf_registry.is_valid_field("class_uid", uid) is True

    # Path C — False (field exists, wrong class)
    def test_valid_field_wrong_class_returns_false(self, ocsf_registry):
        # actor.user.name does not apply to network class 3001
        assert ocsf_registry.is_valid_field("actor.user.name", 3001) is False

    def test_network_bytes_out_wrong_class_returns_false(self, ocsf_registry):
        # network.bytes_out is 3001 only
        assert ocsf_registry.is_valid_field("network.bytes_out", 6003) is False

    # Path B — False (unknown field)
    def test_unknown_field_supported_class_returns_false(self, ocsf_registry):
        assert ocsf_registry.is_valid_field("no.such.field", 6003) is False

    def test_empty_string_field_returns_false(self, ocsf_registry):
        assert ocsf_registry.is_valid_field("", 6003) is False

    # Path A — False (unsupported class)
    @pytest.mark.parametrize("bad_uid", [0, -1, 9999, 1000])
    def test_unsupported_class_returns_false_never_raises(
        self, ocsf_registry, bad_uid
    ):
        assert ocsf_registry.is_valid_field("class_uid", bad_uid) is False

    # None inputs — must never raise per spec
    def test_none_field_path_returns_false_never_raises(self, ocsf_registry):
        assert ocsf_registry.is_valid_field(None, 6003) is False

    def test_none_class_uid_returns_false_never_raises(self, ocsf_registry):
        assert ocsf_registry.is_valid_field("class_uid", None) is False

    def test_both_none_returns_false_never_raises(self, ocsf_registry):
        assert ocsf_registry.is_valid_field(None, None) is False


# ==============================================================================
# TestGetFieldType
# ==============================================================================

class TestGetFieldType:
    """
    Input partitions:
      - Field with each supported type string → correct type returned
      - Unknown field                         → None  (L264 else branch)
      - None field_path                       → None  (no raise)
    """

    def test_integer_field_returns_integer(self, ocsf_registry):
        assert ocsf_registry.get_field_type("class_uid") == "INTEGER"

    def test_timestamp_field_returns_timestamp(self, ocsf_registry):
        assert ocsf_registry.get_field_type("time") == "TIMESTAMP"

    def test_varchar_field_returns_varchar(self, ocsf_registry):
        assert ocsf_registry.get_field_type("metadata.log_source") == "VARCHAR"

    def test_varchar_array_field_returns_varchar_array(self, ocsf_registry):
        assert ocsf_registry.get_field_type("mitre_technique_ids") == "VARCHAR[]"

    def test_unknown_field_returns_none(self, ocsf_registry):
        # Branch L264: fd is None → return None
        assert ocsf_registry.get_field_type("no.such.field") is None

    def test_empty_string_returns_none(self, ocsf_registry):
        assert ocsf_registry.get_field_type("") is None

    def test_none_returns_none_does_not_raise(self, ocsf_registry):
        assert ocsf_registry.get_field_type(None) is None

    def test_partial_path_returns_none(self, ocsf_registry):
        assert ocsf_registry.get_field_type("actor") is None


# ==============================================================================
# TestFieldDefinitionImmutability
# ==============================================================================

class TestFieldDefinitionImmutability:
    """FieldDefinition is frozen=True — no attribute may be set after creation."""

    def test_field_path_is_immutable(self, ocsf_registry):
        fd = ocsf_registry.get_field_definition("class_uid")
        with pytest.raises((AttributeError, TypeError)):
            fd.field_path = "mutated"

    def test_field_type_is_immutable(self, ocsf_registry):
        fd = ocsf_registry.get_field_definition("class_uid")
        with pytest.raises((AttributeError, TypeError)):
            fd.field_type = "TEXT"

    def test_required_is_immutable(self, ocsf_registry):
        fd = ocsf_registry.get_field_definition("class_uid")
        with pytest.raises((AttributeError, TypeError)):
            fd.required = False

    def test_applicable_classes_is_tuple(self, ocsf_registry):
        fd = ocsf_registry.get_field_definition("class_uid")
        assert isinstance(fd.applicable_classes, tuple)

    def test_source_examples_is_tuple(self, ocsf_registry):
        fd = ocsf_registry.get_field_definition("class_uid")
        assert isinstance(fd.source_examples, tuple)

    def test_field_definition_direct_construction(self):
        fd = FieldDefinition(
            field_path="test.field",
            field_type="VARCHAR",
            required=False,
            applicable_classes=(6003,),
            description="A test field.",
            source_examples=("src_field",),
        )
        assert fd.field_path == "test.field"
        assert fd.field_type == "VARCHAR"
        assert fd.required is False
        assert fd.applicable_classes == (6003,)

    def test_field_definition_not_deletable(self):
        fd = FieldDefinition(
            field_path="test.field",
            field_type="VARCHAR",
            required=False,
            applicable_classes=(6003,),
            description="",
            source_examples=(),
        )
        with pytest.raises((AttributeError, TypeError)):
            del fd.field_path


# ==============================================================================
# TestSchemaVersion
# ==============================================================================

class TestSchemaVersion:

    def test_schema_version_is_string(self, ocsf_registry):
        assert isinstance(ocsf_registry.schema_version, str)

    def test_schema_version_unknown_when_missing(self, tmp_path):
        # Schema file has no "version" key → should default to "unknown"
        data = {"fields": []}
        path = _write_schema(tmp_path, data)
        registry = OCSFFieldRegistry(path)
        assert registry.schema_version == "unknown"