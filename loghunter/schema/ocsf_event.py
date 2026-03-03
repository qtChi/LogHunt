# ==============================================================================
# loghunter/schema/ocsf_event.py
#
# OCSFEvent — canonical normalized data object for all log events.
#
# Per spec section 8:
#   - Validates all fields against OCSFFieldRegistry at construction time.
#   - Unknown fields raise UnknownFieldError immediately — never stored silently.
#   - Produced by all parsers, consumed by storage, querying, and detection.
#   - Six required fields must always be present.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any, Optional

from loghunter.exceptions import UnknownFieldError, UnsupportedClassError
from loghunter.schema.ocsf_field_registry import OCSFFieldRegistry, SUPPORTED_CLASSES

# Required constructor parameter names — these are always stored regardless
# of kwargs validation.
_REQUIRED_FIELDS = (
    "class_uid",
    "activity_id",
    "severity_id",
    "time",
    "metadata.log_source",
    "metadata.original_time",
)


class OCSFEvent:
    """
    Canonical normalized event object produced by all parsers.

    All fields are validated against OCSFFieldRegistry at construction.
    Unknown fields raise UnknownFieldError — schema boundary is enforced
    at construction, not downstream.

    Per spec section 8.
    """

    def __init__(
        self,
        class_uid: int,
        activity_id: int,
        severity_id: int,
        time: datetime,
        metadata_log_source: str,
        metadata_original_time: str,
        registry: OCSFFieldRegistry,
        **kwargs: Any,
    ) -> None:
        """
        Create a new OCSFEvent.

        Args:
            class_uid:               Must be one of {1001,3001,3002,4001,6003}.
            activity_id:             Non-negative integer.
            severity_id:             Integer in range 0–6.
            time:                    Timezone-aware datetime in UTC.
            metadata_log_source:     Non-empty string.
            metadata_original_time:  Non-empty string.
            registry:                Initialized OCSFFieldRegistry instance.
            **kwargs:                Additional OCSF fields in dot-notation.
                                     Any unknown field raises UnknownFieldError.

        Raises:
            TypeError:          If any required argument is None.
            ValueError:         If any required argument value is invalid,
                                or if any kwarg field path is not registered
                                for this class_uid.
            UnknownFieldError:  Subclass of ValueError — unknown field path
                                in kwargs.
            UnsupportedClassError: Subclass of ValueError — unsupported class.
        """
        # --- Type checks on required args ---
        if class_uid is None:
            raise TypeError("class_uid must not be None")
        if activity_id is None:
            raise TypeError("activity_id must not be None")
        if severity_id is None:
            raise TypeError("severity_id must not be None")
        if time is None:
            raise TypeError("time must not be None")
        if metadata_log_source is None:
            raise TypeError("metadata_log_source must not be None")
        if metadata_original_time is None:
            raise TypeError("metadata_original_time must not be None")
        if registry is None:
            raise TypeError("registry must not be None")

        # --- Value validation ---
        if class_uid not in SUPPORTED_CLASSES:
            raise UnsupportedClassError(
                f"class_uid {class_uid} is not supported. "
                f"Supported: {sorted(SUPPORTED_CLASSES)}"
            )
        if not isinstance(activity_id, int) or isinstance(activity_id, bool):
            raise TypeError("activity_id must be an integer")
        if activity_id < 0:
            raise ValueError("activity_id must be a non-negative integer")
        if not isinstance(severity_id, int) or isinstance(severity_id, bool):
            raise TypeError("severity_id must be an integer")
        if not (0 <= severity_id <= 6):
            raise ValueError("severity_id must be in range 0–6")
        if not isinstance(time, datetime):
            raise TypeError("time must be a datetime instance")
        if time.tzinfo is None:
            raise ValueError("time must be timezone-aware")
        if not isinstance(metadata_log_source, str) or not metadata_log_source.strip():
            raise ValueError("metadata_log_source must be a non-empty string")
        if not isinstance(metadata_original_time, str) or not metadata_original_time.strip():
            raise ValueError("metadata_original_time must be a non-empty string")
        if not isinstance(registry, OCSFFieldRegistry):
            raise TypeError("registry must be an OCSFFieldRegistry instance")

        # --- Store required fields ---
        self._registry = registry
        self._class_uid = class_uid
        self._fields: dict[str, Any] = {
            "class_uid": class_uid,
            "activity_id": activity_id,
            "severity_id": severity_id,
            "time": time,
            "metadata.log_source": metadata_log_source,
            "metadata.original_time": metadata_original_time,
        }

        # --- Validate and store kwargs ---
        for field_path, value in kwargs.items():
            if not registry.is_valid_field(field_path, class_uid):
                raise UnknownFieldError(
                    f"Field '{field_path}' is not a registered field for "
                    f"class_uid {class_uid}. Use registry.get_fields_for_class"
                    f"({class_uid}) to see valid fields."
                )
            self._fields[field_path] = value

    # --------------------------------------------------------------------------
    # Public API — per spec section 8
    # --------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """
        Return a flat dictionary of all fields using dot-notation keys.

        None fields are included — never omitted.
        Always contains at minimum the six required fields.

        Returns:
            Dict mapping field_path strings to values.
        """
        return dict(self._fields)

    def get_field(self, field_path: str) -> Any:
        """
        Return the value of a field by dot-notation path.

        Returns None if the field is registered but not set on this event.

        Args:
            field_path: Dot-notation path string.

        Returns:
            Field value or None if not set.

        Raises:
            TypeError:  If field_path is None.
            ValueError: If field_path is not a registered field for this class.
        """
        if field_path is None:
            raise TypeError("field_path must not be None")
        if not self._registry.is_valid_field(field_path, self._class_uid):
            raise ValueError(
                f"Field '{field_path}' is not a registered field for "
                f"class_uid {self._class_uid}."
            )
        return self._fields.get(field_path)

    def set_field(self, field_path: str, value: Any) -> None:
        """
        Set a field value post-construction.

        Used by OCSFNormalizer to populate derived fields such as
        mitre_technique_ids after initial construction.

        Args:
            field_path: Dot-notation path string. Must be registered.
            value:      Value to set.

        Raises:
            TypeError:  If field_path is None.
            ValueError: If field_path is not registered for this class.
        """
        if field_path is None:
            raise TypeError("field_path must not be None")
        if not self._registry.is_valid_field(field_path, self._class_uid):
            raise ValueError(
                f"Field '{field_path}' is not a registered field for "
                f"class_uid {self._class_uid}."
            )
        self._fields[field_path] = value

    def validate(self) -> list[str]:
        """
        Validate the event against OCSF schema rules for its class.

        Never raises — all errors returned as strings.

        Checks:
          - Required fields are not None.
          - severity_id in 0–6.
          - time is timezone-aware.
          - IP fields are valid IPv4 or IPv6 strings.
          - Port fields are in range 0–65535.

        Returns:
            List of error strings. Empty list if fully valid.
        """
        errors: list[str] = []

        # Required fields present
        for field_path in _REQUIRED_FIELDS:
            if self._fields.get(field_path) is None:
                errors.append(f"Required field '{field_path}' is None.")

        # severity_id range
        severity = self._fields.get("severity_id")
        if severity is not None and not (0 <= severity <= 6):
            errors.append(
                f"severity_id {severity} is out of range 0–6."
            )

        # time is timezone-aware
        t = self._fields.get("time")
        if t is not None and isinstance(t, datetime) and t.tzinfo is None:
            errors.append("time is not timezone-aware.")

        # IP field validation
        ip_fields = [
            "src_endpoint.ip",
            "dst_endpoint.ip",
        ]
        for ip_field in ip_fields:
            ip_val = self._fields.get(ip_field)
            if ip_val is not None:
                try:
                    ipaddress.ip_address(ip_val)
                except ValueError:
                    errors.append(
                        f"Field '{ip_field}' value '{ip_val}' is not a "
                        f"valid IPv4 or IPv6 address."
                    )

        # Port field validation
        port_fields = [
            "src_endpoint.port",
            "dst_endpoint.port",
        ]
        for port_field in port_fields:
            port_val = self._fields.get(port_field)
            if port_val is not None:
                if not isinstance(port_val, int) or not (0 <= port_val <= 65535):
                    errors.append(
                        f"Field '{port_field}' value '{port_val}' is not "
                        f"in range 0–65535."
                    )

        return errors

    def get_class_uid(self) -> int:
        """Return class_uid."""
        return self._class_uid

    def get_time(self) -> datetime:
        """Return the UTC datetime."""
        return self._fields["time"]

    def __eq__(self, other: object) -> bool:
        """
        Equal if and only if class_uid, time, metadata_log_source, and
        metadata_original_time all match.

        Returns False for non-OCSFEvent comparisons — never raises.
        """
        if not isinstance(other, OCSFEvent):
            return False
        return (
            self._fields["class_uid"] == other._fields["class_uid"]
            and self._fields["time"] == other._fields["time"]
            and self._fields["metadata.log_source"] == other._fields["metadata.log_source"]
            and self._fields["metadata.original_time"] == other._fields["metadata.original_time"]
        )

    def __repr__(self) -> str:
        """
        Returns e.g.:
        OCSFEvent(class_uid=6003, source=evtx, time=2026-03-01T14:32:11Z)
        """
        t = self._fields["time"]
        time_str = t.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(t, datetime) else str(t)
        return (
            f"OCSFEvent("
            f"class_uid={self._class_uid}, "
            f"source={self._fields['metadata.log_source']}, "
            f"time={time_str})"
        )

    def __hash__(self) -> int:
        """Hash based on the same four fields used in __eq__."""
        return hash((
            self._fields["class_uid"],
            self._fields["time"],
            self._fields["metadata.log_source"],
            self._fields["metadata.original_time"],
        ))