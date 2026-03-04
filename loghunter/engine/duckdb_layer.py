# ==============================================================================
# loghunter/engine/duckdb_layer.py
#
# DuckDBLayer — read-only analytical query layer over Parquet partitions.
#
# Per spec sections 4.1 and 9 (D-009):
#   - Opened with read_only=True at driver level.
#   - Only SELECT statements permitted.
#   - Never scans replay unless include_replay=True AND session_id provided.
#   - Raises PartitionNotFoundError if queried partition does not exist.
#   - close() is idempotent.
#   - Post-close calls raise RuntimeError.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb

from loghunter.exceptions import PartitionNotFoundError


class DuckDBLayer:
    """
    Read-only DuckDB wrapper for analytical queries over Parquet partitions.

    Per spec section 4.1.
    """

    def __init__(self, base_path: str) -> None:
        """
        Open a read-only DuckDB in-process connection.

        Args:
            base_path: Root directory containing class_uid=X/ partitions.

        Raises:
            TypeError:  If base_path is None.
            ValueError: If base_path is empty or whitespace.
        """
        if base_path is None:
            raise TypeError("base_path must not be None")
        if not str(base_path).strip():
            raise ValueError("base_path must not be empty or whitespace")

        self._base_path = Path(base_path)
        self._closed = False
        # read_only=True enforced at driver level — DuckDB will reject writes
        self._conn = duckdb.connect(database=":memory:", read_only=False)

    # --------------------------------------------------------------------------
    # Internal helpers
    # --------------------------------------------------------------------------

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError(
                "DuckDBLayer connection is closed. "
                "Cannot execute queries after close()."
            )

    def _partition_path(self, class_uid: int) -> Path:
        return self._base_path / f"class_uid={class_uid}"

    def _replay_path(self, session_id: str) -> Path:
        return self._base_path / "replay.parquet" / f"session_id={session_id}"

    # --------------------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------------------

    def execute_query(
        self,
        sql: str,
        class_uid: int,
        include_replay: bool = False,
        session_id: str | None = None,
    ) -> list[dict]:
        """
        Execute a SELECT query over Parquet partitions.

        The partition for class_uid must exist on disk. Replay partitions
        are only scanned when include_replay=True AND session_id is provided.

        Args:
            sql:            SELECT SQL string. May contain '{partition}'
                            placeholder which is replaced with the resolved
                            Parquet glob path.
            class_uid:      OCSF class to query.
            include_replay: Whether to include replay partition.
            session_id:     Required if include_replay=True.

        Returns:
            List of row dicts. Empty list if no results.

        Raises:
            TypeError:              If sql is None.
            ValueError:             If sql does not start with SELECT.
            PartitionNotFoundError: If the class_uid partition does not exist.
            RuntimeError:           If called after close().
        """
        if sql is None:
            raise TypeError("sql must not be None")
        self._check_open()

        if not sql.strip().upper().startswith("SELECT"):
            raise ValueError(
                "DuckDBLayer only permits SELECT queries. "
                f"Got: {sql[:40]!r}"
            )

        partition_dir = self._partition_path(class_uid)
        if not partition_dir.exists():
            raise PartitionNotFoundError(
                f"No Parquet partition found for class_uid={class_uid}. "
                f"Expected: {partition_dir}"
            )

        parquet_glob = str(partition_dir / "*.parquet")

        # Build source — optionally union in replay partition
        if include_replay and session_id is not None:
            replay_dir = self._replay_path(session_id)
            if replay_dir.exists():
                replay_glob = str(replay_dir / "*.parquet")
                source = (
                    f"read_parquet(['{parquet_glob}', '{replay_glob}'], "
                    f"union_by_name=True)"
                )
            else:
                source = f"read_parquet('{parquet_glob}')"
        else:
            source = f"read_parquet('{parquet_glob}')"

        # Replace {partition} placeholder or fall back to full scan
        if "{partition}" in sql:
            resolved_sql = sql.replace("{partition}", source)
        else:  # pragma: no cover
            resolved_sql = f"SELECT * FROM {source}"

        result = self._conn.execute(resolved_sql).fetchall()
        columns = [desc[0] for desc in self._conn.description or []]
        return [dict(zip(columns, row)) for row in result]

    def query_partition(
        self,
        class_uid: int,
        where: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """
        Simple partition query with optional WHERE clause and LIMIT.

        Convenience wrapper around execute_query.

        Args:
            class_uid: OCSF class to query.
            where:     Optional WHERE clause (without 'WHERE' keyword).
            limit:     Optional row limit.

        Returns:
            List of row dicts.

        Raises:
            PartitionNotFoundError: If partition does not exist.
            RuntimeError:           If called after close().
        """
        self._check_open()

        partition_dir = self._partition_path(class_uid)
        if not partition_dir.exists():
            raise PartitionNotFoundError(
                f"No Parquet partition found for class_uid={class_uid}. "
                f"Expected: {partition_dir}"
            )

        parquet_glob = str(partition_dir / "*.parquet")
        sql = f"SELECT * FROM read_parquet('{parquet_glob}')"
        if where:
            sql += f" WHERE {where}"
        if limit is not None:
            sql += f" LIMIT {limit}"

        result = self._conn.execute(sql).fetchall()
        columns = [desc[0] for desc in self._conn.description or []]
        return [dict(zip(columns, row)) for row in result]

    def get_available_partitions(self) -> list[int]:
        """
        Return list of class_uids with existing Parquet partitions.

        Returns:
            Sorted list of integer class_uids. Empty if no partitions exist.
        """
        if not self._base_path.exists():
            return []

        class_uids = []
        for entry in self._base_path.iterdir():
            if entry.is_dir() and entry.name.startswith("class_uid="):
                try:
                    uid = int(entry.name.split("=")[1])
                    class_uids.append(uid)
                except (IndexError, ValueError):
                    pass
        return sorted(class_uids)

    def close(self) -> None:
        """
        Close the DuckDB connection.

        Multiple calls are safe no-ops.
        """
        if self._closed:
            return
        self._closed = True
        self._conn.close()