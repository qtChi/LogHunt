"""
ReplayEngine — Phase 2
Manages isolated replay sessions for rule backtesting.
The ONLY entry point that passes include_replay=True to DuckDBLayer
(in test_rule_against_session, delegating through SigmaEngine).
"""
from __future__ import annotations

import uuid
from typing import Optional

from loghunter.engine.duckdb_layer import DuckDBLayer
from loghunter.engine.sigma_engine import BacktestResult, SigmaEngine
from loghunter.exceptions import ReplaySessionNotFoundError
from loghunter.ingest.writer import ParquetWriter
from loghunter.schema.ocsf_event import OCSFEvent


class ReplayEngine:
    """
    Creates isolated replay sessions in Parquet and backtests Sigma rules
    against them.
    """

    def __init__(
        self,
        parquet_writer: ParquetWriter,
        sigma_engine: SigmaEngine,
        duckdb_layer: DuckDBLayer,
    ) -> None:
        """
        Raises TypeError if any argument is None.
        """
        if parquet_writer is None:
            raise TypeError("parquet_writer must not be None")
        if sigma_engine is None:
            raise TypeError("sigma_engine must not be None")
        if duckdb_layer is None:
            raise TypeError("duckdb_layer must not be None")

        self._writer = parquet_writer
        self._sigma = sigma_engine
        self._duckdb = duckdb_layer

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_session(self, name: str) -> str:
        """
        Allocate a new replay session UUID.  Does not write to disk —
        session_id is merely a handle until events are ingested.

        Args:
            name: Human-readable label for the session (not persisted to
                  disk; used for audit purposes).

        Returns:
            session_id (UUID4 string).

        Raises:
            TypeError:  If name is None.
            ValueError: If name is empty/whitespace.
        """
        if name is None:
            raise TypeError("name must not be None")
        if not str(name).strip():
            raise ValueError("name must not be empty")

        return str(uuid.uuid4())

    def ingest_to_session(
        self,
        events: list[OCSFEvent],
        session_id: str,
        source_format: str = "replay",
    ) -> int:
        """
        Write *events* into the isolated replay partition for *session_id*.

        Returns:
            Count of events written.

        Raises:
            TypeError:                   If events or session_id is None.
            ValueError:                  If session_id is empty.
            ReplaySessionNotFoundError:  If the replay directory cannot
                                         be created (propagated from
                                         ParquetWriter.write_replay_batch).
        """
        if events is None:
            raise TypeError("events must not be None")
        if session_id is None:
            raise TypeError("session_id must not be None")
        if not str(session_id).strip():
            raise ValueError("session_id must not be empty")

        return self._writer.write_replay_batch(
            events=events,
            session_id=session_id,
            source_format=source_format,
        )

    def test_rule_against_session(
        self, rule_id: str, session_id: str
    ) -> BacktestResult:
        """
        The **only** entry point that passes ``include_replay=True`` to
        DuckDBLayer (via SigmaEngine.backtest_rule).

        Raises:
            TypeError:         If rule_id or session_id is None.
            RuleNotFoundError: If rule_id is unknown (raised by SigmaEngine).
        """
        if rule_id is None:
            raise TypeError("rule_id must not be None")
        if session_id is None:
            raise TypeError("session_id must not be None")

        return self._sigma.backtest_rule(rule_id, session_id)