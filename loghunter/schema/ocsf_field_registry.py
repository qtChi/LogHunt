# ==============================================================================
# loghunter/schema/ocsf_field_registry.py
#
# OCSFFieldRegistry — central schema authority for all OCSF field definitions.
#
# Per spec section 6:
#   - Loaded once at startup from a versioned JSON schema file.
#   - Single source of truth for which fields exist, their types, whether
#     they are required, and which event classes they belong to.
#   - Immutable after construction — no fields can be added or removed.
#   - Both OCSFEvent and OCSFNormalizer depend on it.
#
# Build Priority: Phase 1 — must exist before OCSFEvent.
# ==============================================================================

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from loghunter.exceptions import UnsupportedClassError

SUPPORTED_CLASSES: frozenset[int] = frozenset({1001, 3001, 3002, 4001, 6003})


@dataclass(frozen=True)
class FieldDefinition:
    """
    Immutable descriptor for a single OCSF field.

    Per spec section 6: read-only data class — no setters.

    Attributes:
        field_path:         Dot-notation path e.g. "actor.user.name".
        field_type:         Declared type string e.g. "VARCHAR", "INTEGER",
                            "TIMESTAMP", "VARCHAR[]".
        required:           True if the field is mandatory for its classes.
        applicable_classes: List of class_uid integers this field applies to.
        description:        Human-readable description of the field.
        source_examples:    Example source field names that map to this field.
    """
    field_path: str
    field_type: str
    required: bool
    applicable_classes: tuple[int, ...]
    description: str
    source_examples: tuple[str, ...]


class OCSFFieldRegistry:
    """
    Central schema authority for all OCSF field definitions.

    Loaded once from a versioned JSON schema file. Immutable after
    construction. Both OCSFEvent and OCSFNormalizer depend on this class
    to validate field paths and types.

    Per spec section 6.
    """

    def __init__(self, schema_path: str) -> None:
        """
        Load the OCSF field schema from a JSON file at schema_path.

        Args:
            schema_path: Path to the ocsf_schema.json file.

        Raises:
            TypeError:        If schema_path is None.
            FileNotFoundError: If path does not exist.
            ValueError:       If JSON is malformed or missing required
                              structure.
        """
        if schema_path is None:
            raise TypeError("schema_path must not be None")
        if not str(schema_path).strip():
            raise ValueError("schema_path must not be empty or whitespace")

        path = Path(schema_path)
        if not path.exists():
            raise FileNotFoundError(
                f"OCSF schema file not found: {schema_path}"
            )

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"OCSF schema file is not valid JSON: {exc}"
            ) from exc

        if "fields" not in raw or not isinstance(raw["fields"], list):
            raise ValueError(
                "OCSF schema JSON must contain a top-level 'fields' list."
            )

        # _by_path: field_path -> FieldDefinition
        # _by_class: class_uid -> list[FieldDefinition]
        self._by_path: dict[str, FieldDefinition] = {}
        self._by_class: dict[int, list[FieldDefinition]] = {
            uid: [] for uid in SUPPORTED_CLASSES
        }

        for raw_field in raw["fields"]:
            fd = self._parse_field(raw_field)

            # A field_path may appear multiple times in the JSON with
            # different applicable_classes (e.g. dst_endpoint.hostname).
            # Merge applicable_classes rather than overwrite.
            if fd.field_path in self._by_path:
                existing = self._by_path[fd.field_path]
                merged_classes = tuple(
                    sorted(set(existing.applicable_classes) | set(fd.applicable_classes))
                )
                fd = FieldDefinition(
                    field_path=fd.field_path,
                    field_type=fd.field_type,
                    required=fd.required or existing.required,
                    applicable_classes=merged_classes,
                    description=fd.description or existing.description,
                    source_examples=tuple(
                        dict.fromkeys(existing.source_examples + fd.source_examples)
                    ),
                )

            self._by_path[fd.field_path] = fd

            for class_uid in fd.applicable_classes:
                if class_uid in self._by_class:
                    # Avoid duplicates after merge
                    existing_paths = {
                        f.field_path for f in self._by_class[class_uid]
                    }
                    if fd.field_path not in existing_paths:
                        self._by_class[class_uid].append(fd)
                    else:
                        # Replace with merged version
                        self._by_class[class_uid] = [
                            fd if f.field_path == fd.field_path else f
                            for f in self._by_class[class_uid]
                        ]

        self._schema_version: str = raw.get("version", "unknown")

    # --------------------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------------------

    def _parse_field(self, raw: dict) -> FieldDefinition:
        """Parse and validate a single field dict from the JSON schema."""
        required_keys = {"field_path", "field_type", "required",
                         "applicable_classes"}
        missing = required_keys - raw.keys()
        if missing:
            raise ValueError(
                f"Field definition missing required keys {missing}: {raw}"
            )

        applicable = tuple(int(c) for c in raw["applicable_classes"])

        return FieldDefinition(
            field_path=str(raw["field_path"]),
            field_type=str(raw["field_type"]),
            required=bool(raw["required"]),
            applicable_classes=applicable,
            description=str(raw.get("description", "")),
            source_examples=tuple(raw.get("source_examples", [])),
        )

    # --------------------------------------------------------------------------
    # Public API — per spec section 6
    # --------------------------------------------------------------------------

    def get_field_definition(self, field_path: str) -> Optional[FieldDefinition]:
        """
        Return the FieldDefinition for a dot-notation field path.

        Returns None if not defined — never raises on unknown field.
        None is the correct signal for unknown fields and is used by
        OCSFEvent constructor validation.

        Args:
            field_path: Dot-notation path e.g. "actor.user.name".

        Returns:
            FieldDefinition or None.
        """
        return self._by_path.get(field_path)

    def get_fields_for_class(self, class_uid: int) -> list[FieldDefinition]:
        """
        Return all FieldDefinitions applicable to a given event class,
        including both universal and class-specific fields.

        Args:
            class_uid: One of {1001, 3001, 3002, 4001, 6003}.

        Returns:
            Non-empty list of FieldDefinition objects.

        Raises:
            UnsupportedClassError: If class_uid is not a supported class.
        """
        if class_uid not in SUPPORTED_CLASSES:
            raise UnsupportedClassError(
                f"class_uid {class_uid} is not supported. "
                f"Supported classes: {sorted(SUPPORTED_CLASSES)}"
            )
        return list(self._by_class[class_uid])

    def get_required_fields(self, class_uid: int) -> list[str]:
        """
        Return dot-notation paths of all required fields for a class.

        Args:
            class_uid: One of {1001, 3001, 3002, 4001, 6003}.

        Returns:
            List of required field path strings.

        Raises:
            UnsupportedClassError: If class_uid is not supported.
        """
        return [
            fd.field_path
            for fd in self.get_fields_for_class(class_uid)
            if fd.required
        ]

    def is_valid_field(self, field_path: str, class_uid: int) -> bool:
        """
        Return True if field_path is a valid registered field for class_uid.

        Never raises — unknown fields and unsupported classes both return False.

        Args:
            field_path: Dot-notation path string.
            class_uid:  Event class identifier.

        Returns:
            True if valid, False otherwise.
        """
        if class_uid not in SUPPORTED_CLASSES:
            return False
        fd = self._by_path.get(field_path)
        if fd is None:
            return False
        return class_uid in fd.applicable_classes

    def get_field_type(self, field_path: str) -> Optional[str]:
        """
        Return the declared type string for a field.

        Returns None if the field is not in the registry.

        Args:
            field_path: Dot-notation path string.

        Returns:
            Type string e.g. "VARCHAR", "INTEGER", "TIMESTAMP", "VARCHAR[]",
            or None.
        """
        fd = self._by_path.get(field_path)
        return fd.field_type if fd is not None else None

    @property
    def schema_version(self) -> str:
        """The version string from the loaded schema file."""
        return self._schema_version