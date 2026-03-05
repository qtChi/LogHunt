# ==============================================================================
# loghunter/engine/coverage.py
#
# CoverageEngine — ATT&CK coverage aggregation.
#
# Per spec section 9.10 (Phase 3):
#   - Aggregates coverage from MitreMapper built-in rules and confirmed
#     Sigma rules.
#   - Pure computation — no Streamlit imports, no writes to any store.
#   - Always returns 16 records (one per built-in technique).
#   - Sorted by TACTIC_ORDER then technique ID within each tactic.
#
# Build Priority: Phase 3 — #4 in dependency order.
# ==============================================================================

from __future__ import annotations

from dataclasses import dataclass

from loghunter.engine.mitre_mapper import MitreMapper
from loghunter.engine.sigma_engine import SigmaEngine
from loghunter.schema.ocsf_field_registry import SUPPORTED_CLASSES

TACTIC_ORDER: list[str] = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control",
    "Impact",
]

# Technique ID → tactic name mapping for the 16 built-in rules.
TECHNIQUE_TACTIC_MAP: dict[str, str] = {
    "T1078":     "Defense Evasion",
    "T1078.002": "Defense Evasion",
    "T1110":     "Credential Access",
    "T1110.001": "Credential Access",
    "T1059":     "Execution",
    "T1059.001": "Execution",
    "T1059.007": "Execution",
    "T1055":     "Defense Evasion",
    "T1053":     "Persistence",
    "T1071":     "Command and Control",
    "T1048":     "Exfiltration",
    "T1090":     "Command and Control",
    "T1046":     "Discovery",
    "T1190":     "Initial Access",
    "T1005":     "Collection",
    "T1070.004": "Defense Evasion",
}

# Pre-computed tactic → index for sort key
_TACTIC_INDEX: dict[str, int] = {t: i for i, t in enumerate(TACTIC_ORDER)}


@dataclass
class TechniqueCoverage:
    """
    Coverage record for a single ATT&CK technique.

    Attributes:
        technique_id:   MITRE technique ID e.g. "T1078"
        tactic:         Parent tactic name
        has_rule_match: True if MitreMapper has a built-in rule for this
                        technique (always True for the 16 built-in techniques)
        has_sigma_rule: True if at least one confirmed Sigma rule references
                        this technique ID in its YAML content
        class_uids:     OCSF classes covered by built-in rules for this
                        technique
    """
    technique_id: str
    tactic: str
    has_rule_match: bool
    has_sigma_rule: bool
    class_uids: list[int]


class CoverageEngine:
    """
    Aggregates ATT&CK coverage from MitreMapper built-in rules and
    confirmed Sigma rules. Read-only — never modifies any state.
    """

    def __init__(
        self,
        mitre_mapper: MitreMapper,
        sigma_engine: SigmaEngine,
    ) -> None:
        """
        Args:
            mitre_mapper:  Initialised MitreMapper instance.
            sigma_engine:  Initialised SigmaEngine instance.

        Raises:
            TypeError: If either argument is None.
        """
        if mitre_mapper is None:
            raise TypeError("mitre_mapper must not be None")
        if sigma_engine is None:
            raise TypeError("sigma_engine must not be None")

        self._mapper = mitre_mapper
        self._sigma = sigma_engine

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_coverage_matrix(self) -> list[TechniqueCoverage]:
        """
        Return coverage records for all 16 built-in techniques.

        For each technique:
          - has_rule_match: always True (all 16 have built-in rules)
          - has_sigma_rule: True if any confirmed rule's YAML contains
            the technique ID as a substring
          - class_uids: collected from MitreMapper across all 5 classes

        Returns:
            List of TechniqueCoverage sorted by tactic order then
            technique ID. Always returns 16 records.
            Never raises.
        """
        try:
            confirmed_yamls = self._get_confirmed_yamls()
            class_uid_map = self._build_class_uid_map()

            records: list[TechniqueCoverage] = []
            for technique_id, tactic in TECHNIQUE_TACTIC_MAP.items():
                has_sigma = self._technique_in_sigma(
                    technique_id, confirmed_yamls
                )
                records.append(
                    TechniqueCoverage(
                        technique_id=technique_id,
                        tactic=tactic,
                        has_rule_match=True,
                        has_sigma_rule=has_sigma,
                        class_uids=class_uid_map.get(technique_id, []),
                    )
                )

            return sorted(
                records,
                key=lambda r: (
                    _TACTIC_INDEX.get(r.tactic, len(TACTIC_ORDER)),
                    r.technique_id,
                ),
            )
        except Exception:
            return []

    def get_coverage_summary(self) -> dict:
        """
        Return high-level summary statistics.

        Returns dict with keys:
            total_techniques:      int — always 16
            rule_match_count:      int — techniques with built-in rules
                                   (always 16)
            sigma_confirmed_count: int — techniques also covered by
                                   confirmed Sigma
            coverage_percent:      float — sigma_confirmed_count /
                                   total * 100
            by_tactic:             dict[str, int] — tactic → technique
                                   count
            uncovered_techniques:  list[str] — technique IDs with no
                                   Sigma coverage

        Never raises.
        """
        try:
            matrix = self.get_coverage_matrix()
            total = len(TECHNIQUE_TACTIC_MAP)
            sigma_count = sum(1 for r in matrix if r.has_sigma_rule)

            by_tactic: dict[str, int] = {}
            for r in matrix:
                by_tactic[r.tactic] = by_tactic.get(r.tactic, 0) + 1

            uncovered = [
                r.technique_id for r in matrix if not r.has_sigma_rule
            ]

            return {
                "total_techniques": total,
                "rule_match_count": total,
                "sigma_confirmed_count": sigma_count,
                "coverage_percent": (sigma_count / total * 100)
                if total > 0
                else 0.0,
                "by_tactic": by_tactic,
                "uncovered_techniques": uncovered,
            }
        except Exception:
            return {
                "total_techniques": 0,
                "rule_match_count": 0,
                "sigma_confirmed_count": 0,
                "coverage_percent": 0.0,
                "by_tactic": {},
                "uncovered_techniques": [],
            }

    def get_techniques_for_tactic(self, tactic: str) -> list[TechniqueCoverage]:
        """
        Return coverage records filtered by tactic name.

        Args:
            tactic: Tactic name string e.g. "Execution"

        Returns:
            List of TechniqueCoverage for that tactic. Empty if none.

        Raises:
            TypeError:  If tactic is None.
            ValueError: If tactic is empty/whitespace.
        """
        if tactic is None:
            raise TypeError("tactic must not be None")
        if not str(tactic).strip():
            raise ValueError("tactic must not be empty or whitespace")

        matrix = self.get_coverage_matrix()
        return [r for r in matrix if r.tactic == tactic]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_confirmed_yamls(self) -> list[str]:
        """
        Return list of yaml_content strings from all confirmed Sigma rules.
        Returns empty list on any error.
        """
        try:
            rules = self._sigma.list_rules(confirmed_only=True)
            return [
                str(r["yaml_content"])
                for r in rules
                if r.get("yaml_content")
            ]
        except Exception:
            return []

    def _build_class_uid_map(self) -> dict[str, list[int]]:
        """
        Build a mapping of technique_id → list of class_uids that have
        a built-in rule for that technique.
        """
        result: dict[str, list[int]] = {}
        for class_uid in SUPPORTED_CLASSES:
            for rule in self._mapper.get_rules_for_class(class_uid):
                if rule.technique_id not in result:
                    result[rule.technique_id] = []
                if class_uid not in result[rule.technique_id]:
                    result[rule.technique_id].append(class_uid)
        # Sort for determinism
        for uid_list in result.values():
            uid_list.sort()
        return result

    @staticmethod
    def _technique_in_sigma(
        technique_id: str, confirmed_yamls: list[str]
    ) -> bool:
        """
        Return True if technique_id appears as a substring in any
        confirmed Sigma rule YAML.
        """
        for yaml_content in confirmed_yamls:
            if technique_id in yaml_content:
                return True
        return False