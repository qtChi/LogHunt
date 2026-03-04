"""
SigmaEngine — Phase 2
Sigma rule lifecycle: store, confirm, export, backtest.
Zero LLM imports (D-010).
All rule versions preserved — no DELETE (D-005).
Only confirmed rules are exportable (D-005).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from loghunter.audit.logger import AuditLogger
from loghunter.engine.duckdb_layer import DuckDBLayer
from loghunter.engine.sqlite_layer import SQLiteLayer
from loghunter.exceptions import RuleNotConfirmedError, RuleNotFoundError
from loghunter.schema.audit_models import RuleAuditEntry


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass
class BacktestResult:
    """Result of running a Sigma rule against a replay session."""

    rule_id: str
    session_id: str
    matched_events: list[dict] = field(default_factory=list)
    match_count: int = 0
    total_events: int = 0
    executed_at: str = field(default_factory=_now_utc)


class SigmaEngine:
    """
    Manages the full Sigma rule lifecycle:
    store → confirm → export → backtest.

    SigmaEngine has **zero LLM imports** (D-010). Draft generation
    lives exclusively in ``loghunter.llm.sigma_draft_generator``.
    """

    def __init__(
        self,
        sqlite_layer: SQLiteLayer,
        audit_logger: AuditLogger,
        duckdb_layer: Optional[DuckDBLayer] = None,
    ) -> None:
        """
        Args:
            sqlite_layer:  Mutable application state store.
            audit_logger:  Writes rule lifecycle events to rule_audit.
            duckdb_layer:  Required only for backtest_rule.  May be None
                           if backtest functionality is not used.

        Raises:
            TypeError: If sqlite_layer or audit_logger is None.
        """
        if sqlite_layer is None:
            raise TypeError("sqlite_layer must not be None")
        if audit_logger is None:
            raise TypeError("audit_logger must not be None")

        self._db = sqlite_layer
        self._audit = audit_logger
        self._duckdb = duckdb_layer

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store_rule(self, rule_id: str, yaml_content: str) -> None:
        """
        Persist a Sigma rule.  If *rule_id* already exists, increments
        version and updates yaml_content + sha256 in place.
        New rules start at version=1, analyst_confirmed=0.

        All changes are recorded in rule_audit (event_type='created'
        for new rules, 'updated' for revisions).

        Raises:
            TypeError:  If rule_id or yaml_content is None.
            ValueError: If rule_id or yaml_content is empty/whitespace.
        """
        if rule_id is None:
            raise TypeError("rule_id must not be None")
        if yaml_content is None:
            raise TypeError("yaml_content must not be None")
        if not str(rule_id).strip():
            raise ValueError("rule_id must not be empty")
        if not str(yaml_content).strip():
            raise ValueError("yaml_content must not be empty")

        sha = _sha256(yaml_content)
        existing = self._fetch_rule_row(rule_id)

        if existing is None:
            self._db.execute_write(
                """
                INSERT INTO rules (
                    rule_id, yaml_content, sha256, version,
                    analyst_confirmed, created_at
                ) VALUES (?, ?, ?, 1, 0, ?)
                """,
                (rule_id, yaml_content, sha, _now_utc()),
            )
            event_type = "created"
        else:
            new_version = int(existing["version"]) + 1
            self._db.execute_write(
                """
                UPDATE rules
                   SET yaml_content      = ?,
                       sha256            = ?,
                       version           = ?,
                       analyst_confirmed = 0,
                       confirmed_at      = NULL
                 WHERE rule_id = ?
                """,
                (yaml_content, sha, new_version, rule_id),
            )
            event_type = "updated"

        self._audit.log_rule_event(
            RuleAuditEntry(
                rule_id=rule_id,
                event_type=event_type,
                detail=f"sha256={sha}",
            )
        )

    def confirm_rule(self, rule_id: str, session_id: Optional[str] = None) -> None:
        """
        Mark a rule as analyst-confirmed, enabling export.

        Raises:
            TypeError:        If rule_id is None.
            RuleNotFoundError: If rule_id is not in the rules table.
        """
        if rule_id is None:
            raise TypeError("rule_id must not be None")

        existing = self._fetch_rule_row(rule_id)
        if existing is None:
            raise RuleNotFoundError(f"Rule '{rule_id}' not found")

        confirmed_at = _now_utc()
        self._db.execute_write(
            """
            UPDATE rules
               SET analyst_confirmed = 1,
                   confirmed_at      = ?
             WHERE rule_id = ?
            """,
            (confirmed_at, rule_id),
        )

        self._audit.log_rule_event(
            RuleAuditEntry(
                rule_id=rule_id,
                event_type="confirmed",
                session_id=session_id,
                detail=f"confirmed_at={confirmed_at}",
            )
        )

    def export_rule(self, rule_id: str, format: str = "sigma") -> str:
        """
        Return the YAML content of a confirmed rule and record the export.

        Raises:
            TypeError:            If rule_id is None.
            RuleNotFoundError:    If rule_id is unknown.
            RuleNotConfirmedError: If the rule has not been confirmed
                                   by an analyst (D-005).
        """
        if rule_id is None:
            raise TypeError("rule_id must not be None")

        row = self._fetch_rule_row(rule_id)
        if row is None:
            raise RuleNotFoundError(f"Rule '{rule_id}' not found")
        if not int(row["analyst_confirmed"]):
            raise RuleNotConfirmedError(
                f"Rule '{rule_id}' has not been confirmed by an analyst"
            )

        exported_at = _now_utc()
        self._db.execute_write(
            """
            UPDATE rules
               SET exported_at    = ?,
                   export_format  = ?
             WHERE rule_id = ?
            """,
            (exported_at, format, rule_id),
        )

        self._audit.log_rule_event(
            RuleAuditEntry(
                rule_id=rule_id,
                event_type="exported",
                detail=f"format={format}",
            )
        )

        return str(row["yaml_content"])

    def backtest_rule(
        self, rule_id: str, session_id: str
    ) -> BacktestResult:
        """
        Run a rule's detection logic against a replay session by querying
        DuckDB with ``include_replay=True``.

        This is the **only** method in SigmaEngine that calls DuckDBLayer.

        Raises:
            TypeError:         If rule_id or session_id is None.
            RuleNotFoundError: If rule_id is unknown.
            RuntimeError:      If no DuckDBLayer was provided at construction.
        """
        if rule_id is None:
            raise TypeError("rule_id must not be None")
        if session_id is None:
            raise TypeError("session_id must not be None")
        if self._duckdb is None:
            raise RuntimeError(
                "DuckDBLayer is required for backtest_rule — pass duckdb_layer "
                "to SigmaEngine.__init__"
            )

        row = self._fetch_rule_row(rule_id)
        if row is None:
            raise RuleNotFoundError(f"Rule '{rule_id}' not found")

        # Collect matched events from all supported class partitions
        matched: list[dict] = []
        total = 0
        available = self._duckdb.get_available_partitions()

        for class_uid in available:
            try:
                rows = self._duckdb.execute_query(
                    "SELECT * FROM {partition}",
                    class_uid,
                    include_replay=True,
                    session_id=session_id,
                )
                total += len(rows)
                # Naive match: event is "matched" if it originates from
                # the replay session (more sophisticated Sigma parsing
                # is out of scope for Phase 2 — that requires pySigma
                # integration which is a Phase 3 concern).
                for r in rows:
                    if _event_matches_rule(r, str(row["yaml_content"])):
                        matched.append(dict(r))
            except Exception:
                continue  # partition unavailable — skip

        result = BacktestResult(
            rule_id=rule_id,
            session_id=session_id,
            matched_events=matched,
            match_count=len(matched),
            total_events=total,
        )

        self._audit.log_rule_event(
            RuleAuditEntry(
                rule_id=rule_id,
                event_type="backtested",
                session_id=session_id,
                detail=(
                    f"matched={result.match_count}/"
                    f"total={result.total_events}"
                ),
            )
        )

        return result

    def get_rule(self, rule_id: str) -> dict:
        """
        Return the current rule row as a dict.

        Raises:
            TypeError:        If rule_id is None.
            RuleNotFoundError: If rule_id is unknown.
        """
        if rule_id is None:
            raise TypeError("rule_id must not be None")
        row = self._fetch_rule_row(rule_id)
        if row is None:
            raise RuleNotFoundError(f"Rule '{rule_id}' not found")
        return dict(row)

    def list_rules(self, confirmed_only: bool = False) -> list[dict]:
        """
        Return all rules as a list of dicts, most recently created first.

        Args:
            confirmed_only: When True, only analyst-confirmed rules are
                            returned.
        """
        if confirmed_only:
            rows = self._db.execute_read(
                "SELECT * FROM rules WHERE analyst_confirmed = 1 "
                "ORDER BY created_at DESC",
                (),
            )
        else:
            rows = self._db.execute_read(
                "SELECT * FROM rules ORDER BY created_at DESC",
                (),
            )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_rule_row(self, rule_id: str) -> Optional[dict]:
        rows = self._db.execute_read(
            "SELECT * FROM rules WHERE rule_id = ? LIMIT 1",
            (rule_id,),
        )
        if not rows:
            return None
        return dict(rows[0])


def _event_matches_rule(event_row: dict, yaml_content: str) -> bool:
    """
    Minimal keyword-based Sigma match used for Phase 2 backtesting.
    Checks whether any YAML keywords (from ``keywords:`` or ``value:``
    lines) appear as substrings in event field values.

    Full pySigma-based evaluation is a Phase 3 concern.
    Never raises.
    """
    try:
        import re

        # Extract keywords from YAML — handles both inline and list formats:
        #   keywords: malware        (inline)
        #   keywords:\n    - malware  (list)
        inline = re.findall(
            r"(?:keywords|value):\s+([^\n]+)",
            yaml_content,
            re.IGNORECASE,
        )
        list_items = re.findall(
            r"^\s*-\s+([^\n]+)",
            yaml_content,
            re.MULTILINE,
        )
        keywords = [k.strip().strip("'\"") for k in inline + list_items if k.strip()]
        if not keywords:
            return False

        event_text = " ".join(str(v) for v in event_row.values() if v is not None)
        for kw in keywords:
            if kw and kw.lower() in event_text.lower():
                return True
        return False
    except Exception:
        return False