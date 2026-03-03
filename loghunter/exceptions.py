# ==============================================================================
# loghunter/exceptions.py
#
# Central custom exception hierarchy for LogHunt.
#
# All application-specific exceptions live here so that:
#   - Test assertions use specific types: pytest.raises(UnknownFieldError)
#     rather than the broad built-in ValueError.
#   - UI layers catch specific types and surface meaningful analyst messages.
#   - Every exception has one definition, one location.
#
# All exceptions that subclass ValueError or RuntimeError remain catchable
# by existing broad except blocks — no existing behaviour is broken.
# ==============================================================================


class LogHuntError(Exception):
    """Base class for all LogHunt application exceptions."""


# --- Schema -------------------------------------------------------------------

class SchemaError(LogHuntError):
    """Raised when data violates the OCSF schema contract."""


class UnknownFieldError(SchemaError, ValueError):
    """
    Raised by OCSFEvent when a kwarg field path is not registered in
    OCSFFieldRegistry for the event's class_uid.

    Per spec section 8: unknown fields raise ValueError at construction.
    Subclasses ValueError so broad ValueError catches still work while
    tests can assert on the specific type.
    """


class UnsupportedClassError(SchemaError, ValueError):
    """
    Raised when class_uid is not one of the five supported OCSF classes:
    {1001, 3001, 3002, 4001, 6003}.
    """


# --- Storage ------------------------------------------------------------------

class StorageError(LogHuntError):
    """Raised when a storage operation cannot be completed."""


class PartitionNotFoundError(StorageError, ValueError):
    """
    Raised by QueryBuilder.build_sql when a QueryIntent references an
    event class for which no Parquet partition exists yet.

    The UI catches this specifically to surface:
    "No data ingested yet for this event class."
    """


class ReplaySessionNotFoundError(StorageError, ValueError):
    """
    Raised by ReplayEngine and ParquetWriter when an operation references
    a replay session_id that does not exist on disk.
    """


# --- Registration -------------------------------------------------------------

class RegistrationError(LogHuntError):
    """Raised when a required registration is missing."""


class UnregisteredFormatError(RegistrationError, ValueError):
    """
    Raised by OCSFNormalizer.normalize when source_format has no
    registered field mapping for the given class_uid.
    """


# --- Rules --------------------------------------------------------------------

class RuleError(LogHuntError):
    """Raised for Sigma rule lifecycle violations."""


class RuleNotFoundError(RuleError, ValueError):
    """
    Raised by SigmaEngine when rule_id does not exist in the SQLite
    rule store.
    """


class RuleNotConfirmedError(RuleError, ValueError):
    """
    Raised by SigmaEngine.export_rule when the rule exists but
    analyst_confirmed is False.
    Per spec section 20: only confirmed rules are exportable.
    """