# ==============================================================================
# loghunter/engine/mitre_mapper.py
#
# MitreMapper — deterministic MITRE ATT&CK technique mapping.
#
# Per spec section 13:
#   - Maps OCSFEvent fields to ATT&CK technique IDs using pattern rules.
#   - Pattern rules are defined in code — no external file dependency.
#   - Each rule is a predicate (callable) over an OCSFEvent that returns
#     True if the technique applies.
#   - map_event returns a list of matching technique IDs.
#   - get_coverage returns a dict of class_uid → set of technique IDs
#     that have at least one rule defined.
#   - Per spec decision D-006: absent fields evaluate to False — never raise.
#   - All predicates must be pure functions with no side effects.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # pragma: no cover
    from loghunter.schema.ocsf_event import OCSFEvent

from loghunter.schema.ocsf_field_registry import SUPPORTED_CLASSES


@dataclass(frozen=True)
class MappingRule:
    """
    A single ATT&CK technique mapping rule.

    Attributes:
        technique_id:  MITRE ATT&CK technique ID e.g. "T1078".
        class_uid:     OCSF event class this rule applies to.
        description:   Human-readable description of the pattern.
        predicate:     Callable that takes an OCSFEvent and returns True
                       if this technique applies. Must never raise.
    """
    technique_id: str
    class_uid: int
    description: str
    predicate: Callable[["OCSFEvent"], bool]


# ---------------------------------------------------------------------------
# Predicate helpers — pure functions, never raise
# ---------------------------------------------------------------------------

def _field(event: "OCSFEvent", path: str) -> object:
    """Safely get a field value. Returns None on any error."""
    try:
        return event._fields.get(path)
    except Exception:
        return None


def _eq(event: "OCSFEvent", path: str, value: object) -> bool:
    return _field(event, path) == value


def _contains(event: "OCSFEvent", path: str, substring: str) -> bool:
    val = _field(event, path)
    if val is None:
        return False
    try:
        return substring.lower() in str(val).lower()
    except Exception:
        return False


def _gt(event: "OCSFEvent", path: str, threshold: float) -> bool:
    val = _field(event, path)
    if val is None:
        return False
    try:
        return float(val) > threshold
    except (TypeError, ValueError):
        return False


def _not_none(event: "OCSFEvent", path: str) -> bool:
    return _field(event, path) is not None


# ---------------------------------------------------------------------------
# Built-in mapping rules
# ---------------------------------------------------------------------------

_RULES: list[MappingRule] = [

    # ---- Authentication (class_uid=6003) ------------------------------------

    MappingRule(
        technique_id="T1078",
        class_uid=6003,
        description="Valid Accounts — successful logon with known credentials.",
        predicate=lambda e: _eq(e, "activity_id", 1) and _eq(e, "severity_id", 1),
    ),
    MappingRule(
        technique_id="T1110",
        class_uid=6003,
        description="Brute Force — repeated failed authentication attempts.",
        predicate=lambda e: _eq(e, "activity_id", 2) and _eq(e, "severity_id", 3),
    ),
    MappingRule(
        technique_id="T1110.001",
        class_uid=6003,
        description="Password Guessing — failed logon with type 3 (network) logon.",
        predicate=lambda e: (
            _eq(e, "activity_id", 2)
            and _contains(e, "auth.protocol_name", "ntlm")
        ),
    ),
    MappingRule(
        technique_id="T1078.002",
        class_uid=6003,
        description="Domain Accounts — logon with domain account.",
        predicate=lambda e: (
            _eq(e, "activity_id", 1)
            and _contains(e, "actor.user.name", "\\")
        ),
    ),

    # ---- Process Activity (class_uid=4001) ----------------------------------

    MappingRule(
        technique_id="T1059",
        class_uid=4001,
        description="Command and Scripting Interpreter — cmd.exe or powershell.",
        predicate=lambda e: (
            _contains(e, "actor.process.name", "cmd.exe")
            or _contains(e, "actor.process.name", "powershell")
        ),
    ),
    MappingRule(
        technique_id="T1059.001",
        class_uid=4001,
        description="PowerShell execution.",
        predicate=lambda e: _contains(e, "actor.process.name", "powershell"),
    ),
    MappingRule(
        technique_id="T1055",
        class_uid=4001,
        description="Process Injection — process spawning from unusual parent.",
        predicate=lambda e: (
            _contains(e, "actor.process.name", "svchost")
            and _not_none(e, "process.name")
        ),
    ),
    MappingRule(
        technique_id="T1053",
        class_uid=4001,
        description="Scheduled Task — schtasks or at process execution.",
        predicate=lambda e: (
            _contains(e, "actor.process.name", "schtasks")
            or _contains(e, "actor.process.name", "at.exe")
        ),
    ),

    # ---- Network Activity (class_uid=3001) ----------------------------------

    MappingRule(
        technique_id="T1071",
        class_uid=3001,
        description="Application Layer Protocol — HTTP/HTTPS outbound.",
        predicate=lambda e: (
            _eq(e, "dst_endpoint.port", 80)
            or _eq(e, "dst_endpoint.port", 443)
        ),
    ),
    MappingRule(
        technique_id="T1048",
        class_uid=3001,
        description="Exfiltration Over Alternative Protocol — large outbound transfer.",
        predicate=lambda e: _gt(e, "network.bytes_out", 10_000_000),
    ),
    MappingRule(
        technique_id="T1090",
        class_uid=3001,
        description="Proxy — connection to non-standard high port.",
        predicate=lambda e: _gt(e, "dst_endpoint.port", 8080),
    ),
    MappingRule(
        technique_id="T1046",
        class_uid=3001,
        description="Network Service Discovery — sequential port connections.",
        predicate=lambda e: (
            _not_none(e, "dst_endpoint.port")
            and _eq(e, "network.bytes_out", 0)
        ),
    ),

    # ---- HTTP Activity (class_uid=3002) -------------------------------------

    MappingRule(
        technique_id="T1190",
        class_uid=3002,
        description="Exploit Public-Facing Application — HTTP 500 responses.",
        predicate=lambda e: _contains(e, "http.response.code", "5"),
    ),
    MappingRule(
        technique_id="T1059.007",
        class_uid=3002,
        description="JavaScript — script tags in HTTP request URI.",
        predicate=lambda e: _contains(e, "http.request.url.path", "<script"),
    ),

    # ---- File Activity (class_uid=1001) -------------------------------------

    MappingRule(
        technique_id="T1005",
        class_uid=1001,
        description="Data from Local System — access to sensitive file paths.",
        predicate=lambda e: (
            _contains(e, "file.path", "\\windows\\system32")
            or _contains(e, "file.path", "/etc/passwd")
            or _contains(e, "file.path", "/etc/shadow")
        ),
    ),
    MappingRule(
        technique_id="T1070.004",
        class_uid=1001,
        description="File Deletion — file delete activity.",
        predicate=lambda e: _eq(e, "activity_id", 4),
    ),
]


class MitreMapper:
    """
    Deterministic MITRE ATT&CK technique mapper.

    Maps OCSFEvent instances to matching technique IDs using a fixed
    set of pattern rules. Per spec section 13.
    """

    def __init__(self) -> None:
        # Index rules by class_uid for O(n_rules_for_class) lookup
        self._rules_by_class: dict[int, list[MappingRule]] = {
            uid: [] for uid in SUPPORTED_CLASSES
        }
        for rule in _RULES:
            if rule.class_uid in self._rules_by_class:  # pragma: no branch
                self._rules_by_class[rule.class_uid].append(rule)

    def map_event(self, event: "OCSFEvent") -> list[str]:
        """
        Return all ATT&CK technique IDs matching this event.

        Per spec decision D-006: absent fields evaluate to False.
        Never raises — predicate exceptions return False for that rule.

        Args:
            event: OCSFEvent to evaluate.

        Returns:
            List of technique ID strings. Empty list if no rules match.

        Raises:
            TypeError: If event is None.
        """
        if event is None:
            raise TypeError("event must not be None")

        class_uid = event.get_class_uid()
        rules = self._rules_by_class.get(class_uid, [])

        matched: list[str] = []
        for rule in rules:
            try:
                if rule.predicate(event):
                    matched.append(rule.technique_id)
            except Exception:
                # D-006: predicate errors treated as non-match
                pass

        return matched

    def get_coverage(self) -> dict[int, set[str]]:
        """
        Return a mapping of class_uid → set of technique IDs that have
        at least one rule defined.

        Used by the ATT&CK coverage tab in the UI.

        Returns:
            Dict mapping each supported class_uid to a set of technique
            ID strings. Empty set for classes with no rules.
        """
        return {
            uid: {rule.technique_id for rule in rules}
            for uid, rules in self._rules_by_class.items()
        }

    def get_rules_for_class(self, class_uid: int) -> list[MappingRule]:
        """
        Return all MappingRule objects defined for a given class.

        Args:
            class_uid: OCSF event class identifier.

        Returns:
            List of MappingRule objects. Empty list for unsupported class.
        """
        return list(self._rules_by_class.get(class_uid, []))