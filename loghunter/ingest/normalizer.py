# ==============================================================================
# loghunter/ingest/normalizer.py
#
# OCSFNormalizer — maps raw parsed dicts to OCSFEvent objects.
#
# Per spec section 10:
#   - Field mappings registered per (source_format, class_uid) pair.
#   - Unknown raw fields dropped with audit log entry — never raise.
#   - Calls MitreMapper.map_event() and sets mitre_technique_ids.
#   - normalize() raises UnregisteredFormatError if no mapping registered.
#   - normalize_batch() never raises — failures collected separately.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from loghunter.audit.logger import AuditLogger
from loghunter.engine.mitre_mapper import MitreMapper
from loghunter.exceptions import UnregisteredFormatError
from loghunter.schema.audit_models import IngestAuditEntry
from loghunter.schema.ocsf_event import OCSFEvent
from loghunter.schema.ocsf_field_registry import OCSFFieldRegistry


class OCSFNormalizer:
    """
    Maps raw parsed log dicts to OCSFEvent objects using registered
    field mappings.

    Per spec section 10.
    """

    def __init__(
        self,
        registry: OCSFFieldRegistry,
        mitre_mapper: MitreMapper,
        audit_logger: AuditLogger,
    ) -> None:
        """
        Args:
            registry:     Initialised OCSFFieldRegistry.
            mitre_mapper: Initialised MitreMapper.
            audit_logger: Initialised AuditLogger.

        Raises:
            TypeError: If any argument is None.
        """
        if registry is None:
            raise TypeError("registry must not be None")
        if mitre_mapper is None:
            raise TypeError("mitre_mapper must not be None")
        if audit_logger is None:
            raise TypeError("audit_logger must not be None")

        self._registry = registry
        self._mapper = mitre_mapper
        self._audit = audit_logger

        # _mappings: (source_format, class_uid) -> {raw_field: ocsf_path}
        self._mappings: dict[tuple[str, int], dict[str, str]] = {}

    # --------------------------------------------------------------------------
    # Registration
    # --------------------------------------------------------------------------

    def register_mapping(
        self,
        source_format: str,
        class_uid: int,
        field_map: dict[str, str],
    ) -> None:
        """
        Register a field mapping for a source format and event class.

        Args:
            source_format: Parser source_format string e.g. "zeek_conn".
            class_uid:     Target OCSF class UID.
            field_map:     Dict of raw_field_name → ocsf_dot_notation_path.

        Raises:
            TypeError:  If any argument is None.
            ValueError: If source_format already registered for class_uid,
                        or if field_map is empty.
        """
        if source_format is None:
            raise TypeError("source_format must not be None")
        if class_uid is None:
            raise TypeError("class_uid must not be None")
        if field_map is None:
            raise TypeError("field_map must not be None")
        if not field_map:
            raise ValueError("field_map must not be empty")

        key = (source_format, class_uid)
        if key in self._mappings:
            raise ValueError(
                f"Mapping already registered for source_format="
                f"'{source_format}' class_uid={class_uid}. "
                f"Call register_mapping only once per (format, class) pair."
            )
        self._mappings[key] = dict(field_map)

    # --------------------------------------------------------------------------
    # Normalisation
    # --------------------------------------------------------------------------

    def normalize(
        self,
        raw_dict: dict[str, Any],
        source_format: str,
        class_uid: int,
    ) -> OCSFEvent:
        """
        Normalise a single raw parsed dict to an OCSFEvent.

        Unknown raw fields (not in field_map) are dropped silently.
        Mapped fields that are not registered in OCSFFieldRegistry for the
        target class are also dropped with an audit log entry.

        After construction, calls MitreMapper.map_event() and sets
        mitre_technique_ids on the event.

        Args:
            raw_dict:      Raw parsed field dict from a LogParser.
            source_format: Parser source_format string.
            class_uid:     Target OCSF class UID.

        Returns:
            OCSFEvent with all mappable fields populated.

        Raises:
            TypeError:              If raw_dict or source_format is None.
            UnregisteredFormatError: If no mapping registered for
                                     (source_format, class_uid).
            ValueError:             If required fields cannot be extracted.
        """
        if raw_dict is None:
            raise TypeError("raw_dict must not be None")
        if source_format is None:
            raise TypeError("source_format must not be None")

        key = (source_format, class_uid)
        if key not in self._mappings:
            raise UnregisteredFormatError(
                f"No field mapping registered for source_format="
                f"'{source_format}' class_uid={class_uid}. "
                f"Call register_mapping() first."
            )

        field_map = self._mappings[key]
        dropped: list[str] = []
        ocsf_fields: dict[str, Any] = {}

        for raw_field, value in raw_dict.items():
            ocsf_path = field_map.get(raw_field)
            if ocsf_path is None:
                # Field not in mapping — silently drop
                continue
            if not self._registry.is_valid_field(ocsf_path, class_uid):
                # Mapped path not registered for this class — drop with log
                dropped.append(raw_field)
                continue
            ocsf_fields[ocsf_path] = value

        if dropped:
            self._audit.log_query(
                __import__(
                    "loghunter.schema.audit_models",
                    fromlist=["QueryAuditEntry"]
                ).QueryAuditEntry(
                    session_id="normalizer",
                    sql_template=f"DROPPED_FIELDS:{','.join(dropped)}",
                    event_class=class_uid,
                    success=False,
                    failure_reason=f"Fields not registered for class {class_uid}",
                )
            )

        # Extract required fields from ocsf_fields dict
        event = self._build_event(ocsf_fields, class_uid)

        # Set MITRE technique IDs
        techniques = self._mapper.map_event(event)
        if techniques and self._registry.is_valid_field(
            "mitre_technique_ids", class_uid
        ):
            event.set_field("mitre_technique_ids", techniques)

        return event

    def normalize_batch(
        self,
        raw_dicts: list[dict[str, Any]],
        source_format: str,
        class_uid: int,
    ) -> tuple[list[OCSFEvent], list[dict]]:
        """
        Normalise a list of raw parsed dicts.

        Never raises — failures collected separately.

        Args:
            raw_dicts:     List of raw parsed field dicts.
            source_format: Parser source_format string.
            class_uid:     Target OCSF class UID.

        Returns:
            Tuple of (successes, failures) where failures are the original
            raw dicts that could not be normalised.

        Raises:
            TypeError: If raw_dicts is None.
        """
        if raw_dicts is None:
            raise TypeError("raw_dicts must not be None")

        successes: list[OCSFEvent] = []
        failures: list[dict] = []

        for raw_dict in raw_dicts:
            try:
                event = self.normalize(raw_dict, source_format, class_uid)
                successes.append(event)
            except Exception:
                failures.append(raw_dict)

        ingest_id = str(uuid.uuid4())
        self._audit.log_ingest(
            IngestAuditEntry(
                ingest_id=ingest_id,
                source_format=source_format,
                event_count=len(successes),
                failed_count=len(failures),
            )
        )

        return successes, failures

    # --------------------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------------------

    def _build_event(
        self, ocsf_fields: dict[str, Any], class_uid: int
    ) -> OCSFEvent:
        """
        Construct OCSFEvent from a flat dict of OCSF-mapped fields.

        Extracts required positional arguments. Remaining fields passed
        as kwargs.

        Raises:
            ValueError: If required fields are missing or invalid.
        """
        def _pop(key: str) -> Any:
            return ocsf_fields.pop(key, None)

        _pop("class_uid")  # already passed as positional arg
        raw_time = _pop("time")
        time = self._coerce_time(raw_time)

        event = OCSFEvent(
            class_uid=class_uid,
            activity_id=self._coerce_int(_pop("activity_id"), "activity_id"),
            severity_id=self._coerce_int(_pop("severity_id"), "severity_id"),
            time=time,
            metadata_log_source=str(_pop("metadata.log_source") or "unknown"),
            metadata_original_time=str(_pop("metadata.original_time") or "unknown"),
            registry=self._registry,
            **{k: v for k, v in ocsf_fields.items()},
        )
        return event

    def _coerce_time(self, value: Any) -> datetime:
        """
        Coerce a raw time value to a timezone-aware datetime.

        Accepts: datetime (already tz-aware), Unix timestamp float/str,
        ISO 8601 string.

        Falls back to datetime.now(UTC) if coercion fails.
        """
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value
        if value is None:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            pass
        try:
            dt = datetime.fromisoformat(str(value))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            pass
        return datetime.now(timezone.utc)

    def _coerce_int(self, value: Any, field_name: str) -> int:
        """
        Coerce raw value to int. Raises ValueError if not possible.
        """
        if isinstance(value, bool):
            raise ValueError(
                f"Field '{field_name}' must be an integer, not bool."
            )
        if isinstance(value, int):
            return value
        if value is None:
            raise ValueError(
                f"Required field '{field_name}' is missing from raw dict."
            )
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValueError(
                f"Field '{field_name}' value '{value}' cannot be coerced to int."
            )