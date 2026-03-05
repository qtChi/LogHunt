# ==============================================================================
# tests/testEngine/testDuckdbLayer.py
#
# Tests for loghunter/engine/duckdb_layer.py
#
# Coverage strategy — every branch explicitly targeted:
#
# Constructor:
#   None base_path → TypeError
#   Empty/whitespace → ValueError
#   Valid → constructs
#
# execute_query:
#   None sql → TypeError
#   Non-SELECT → ValueError
#   Partition does not exist → PartitionNotFoundError
#   Valid SELECT → list of dicts
#   Zero results → []
#   include_replay=True, session_id provided, replay dir exists → union
#   include_replay=True, session_id provided, replay dir missing → base only
#   include_replay=False → base only
#   Called after close → RuntimeError
#
# query_partition:
#   Partition does not exist → PartitionNotFoundError
#   Valid → list of dicts
#   where clause applied
#   limit applied
#   Called after close → RuntimeError
#
# get_available_partitions:
#   base_path does not exist → []
#   No partitions → []
#   One partition → [uid]
#   Multiple partitions → sorted list
#   Non-matching dirs skipped
#
# close:
#   Prevents execute_query
#   Prevents query_partition
#   Multiple calls safe
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
from pyarrow import parquet as pq
import pytest

from loghunter.engine.duckdb_layer import DuckDBLayer
from loghunter.exceptions import PartitionNotFoundError
from loghunter.schema.ocsf_event import OCSFEvent

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_layer(tmp_path) -> DuckDBLayer:
    return DuckDBLayer(str(tmp_path / "parquet"))


def _write_partition(base: Path, class_uid: int, rows: list[dict]) -> None:
    """Write a simple Parquet partition for testing."""
    part_dir = base / f"class_uid={class_uid}"
    part_dir.mkdir(parents=True, exist_ok=True)
    if rows:
        table = pa.table({k: [r.get(k) for r in rows] for k in rows[0]})
    else:
        table = pa.table({"class_uid": pa.array([], type=pa.int64())})
    pq.write_table(table, str(part_dir / "part-0000.parquet"))


def _write_replay(base: Path, session_id: str, rows: list[dict]) -> None:
    replay_dir = base / "replay.parquet" / f"session_id={session_id}"
    replay_dir.mkdir(parents=True, exist_ok=True)
    table = pa.table({k: [r.get(k) for r in rows] for k in rows[0]})
    pq.write_table(table, str(replay_dir / "part-0000.parquet"))


_ROWS = [
    {"class_uid": 6003, "activity_id": 1, "severity_id": 1,
     "source": "evtx", "value": 10},
    {"class_uid": 6003, "activity_id": 2, "severity_id": 3,
     "source": "evtx", "value": 20},
]


# ==============================================================================
# TestConstructor
# ==============================================================================

class TestConstructor:

    def test_none_base_path_raises_type_error(self):
        with pytest.raises(TypeError):
            DuckDBLayer(None)

    def test_empty_base_path_raises_value_error(self):
        with pytest.raises(ValueError):
            DuckDBLayer("")

    def test_whitespace_raises_value_error(self):
        with pytest.raises(ValueError):
            DuckDBLayer("   ")

    def test_valid_construction(self, tmp_path):
        layer = _make_layer(tmp_path)
        assert layer is not None
        layer.close()

    def test_nonexistent_path_still_constructs(self, tmp_path):
        # base_path need not exist at construction — only at query time
        layer = DuckDBLayer(str(tmp_path / "nonexistent" / "path"))
        assert layer is not None
        layer.close()


# ==============================================================================
# TestExecuteQuery
# ==============================================================================

class TestExecuteQuery:

    def test_none_sql_raises_type_error(self, tmp_path):
        layer = _make_layer(tmp_path)
        with pytest.raises(TypeError):
            layer.execute_query(None, 6003)
        layer.close()

    def test_non_select_raises_value_error(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        with pytest.raises(ValueError):
            layer.execute_query("INSERT INTO foo VALUES (1)", 6003)
        layer.close()

    def test_missing_partition_raises_partition_not_found(self, tmp_path):
        layer = _make_layer(tmp_path)
        with pytest.raises(PartitionNotFoundError):
            layer.execute_query("SELECT 1", 6003)
        layer.close()

    def test_partition_not_found_is_also_value_error(self, tmp_path):
        layer = _make_layer(tmp_path)
        with pytest.raises(ValueError):
            layer.execute_query("SELECT 1", 6003)
        layer.close()

    def test_valid_query_returns_list_of_dicts(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        results = layer.execute_query(
            "SELECT * FROM {partition}", 6003
        )
        assert isinstance(results, list)
        assert len(results) == 2
        assert isinstance(results[0], dict)
        layer.close()

    def test_empty_partition_returns_empty_list(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, [])
        layer = DuckDBLayer(str(base))
        results = layer.execute_query("SELECT * FROM {partition}", 6003)
        assert results == []
        layer.close()

    def test_include_replay_with_existing_session_unions_data(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS[:1])
        replay_rows = [{"class_uid": 6003, "activity_id": 1,
                        "severity_id": 1, "source": "replay", "value": 99}]
        _write_replay(base, "sess-001", replay_rows)
        layer = DuckDBLayer(str(base))
        results = layer.execute_query(
            "SELECT * FROM {partition}", 6003,
            include_replay=True, session_id="sess-001"
        )
        assert len(results) == 2
        layer.close()

    def test_include_replay_missing_session_uses_base_only(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        results = layer.execute_query(
            "SELECT * FROM {partition}", 6003,
            include_replay=True, session_id="nonexistent-session"
        )
        assert len(results) == 2
        layer.close()

    def test_include_replay_false_ignores_replay(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS[:1])
        replay_rows = [{"class_uid": 6003, "activity_id": 1,
                        "severity_id": 1, "source": "replay", "value": 99}]
        _write_replay(base, "sess-001", replay_rows)
        layer = DuckDBLayer(str(base))
        results = layer.execute_query(
            "SELECT * FROM {partition}", 6003,
            include_replay=False
        )
        assert len(results) == 1
        layer.close()

    def test_include_replay_no_session_id_uses_base_only(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        results = layer.execute_query(
            "SELECT * FROM {partition}", 6003,
            include_replay=True, session_id=None
        )
        assert len(results) == 2
        layer.close()

    def test_called_after_close_raises_runtime_error(self, tmp_path):
        layer = _make_layer(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.execute_query("SELECT 1", 6003)


# ==============================================================================
# TestQueryPartition
# ==============================================================================

class TestQueryPartition:

    def test_missing_partition_raises_error(self, tmp_path):
        layer = _make_layer(tmp_path)
        with pytest.raises(PartitionNotFoundError):
            layer.query_partition(6003)
        layer.close()

    def test_valid_returns_all_rows(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        results = layer.query_partition(6003)
        assert len(results) == 2
        layer.close()

    def test_where_clause_filters_rows(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        results = layer.query_partition(6003, where="activity_id = 1")
        assert len(results) == 1
        assert results[0]["activity_id"] == 1
        layer.close()

    def test_limit_applied(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        results = layer.query_partition(6003, limit=1)
        assert len(results) == 1
        layer.close()

    def test_called_after_close_raises_runtime_error(self, tmp_path):
        layer = _make_layer(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.query_partition(6003)


# ==============================================================================
# TestGetAvailablePartitions
# ==============================================================================

class TestGetAvailablePartitions:

    def test_nonexistent_base_returns_empty(self, tmp_path):
        layer = DuckDBLayer(str(tmp_path / "nonexistent"))
        assert layer.get_available_partitions() == []
        layer.close()

    def test_no_partitions_returns_empty(self, tmp_path):
        base = tmp_path / "parquet"
        base.mkdir()
        layer = DuckDBLayer(str(base))
        assert layer.get_available_partitions() == []
        layer.close()

    def test_one_partition_returned(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 6003, _ROWS)
        layer = DuckDBLayer(str(base))
        assert layer.get_available_partitions() == [6003]
        layer.close()

    def test_multiple_partitions_sorted(self, tmp_path):
        base = tmp_path / "parquet"
        _write_partition(base, 3001, _ROWS)
        _write_partition(base, 6003, _ROWS)
        _write_partition(base, 4001, _ROWS)
        layer = DuckDBLayer(str(base))
        assert layer.get_available_partitions() == [3001, 4001, 6003]
        layer.close()

    def test_non_matching_dirs_skipped(self, tmp_path):
        base = tmp_path / "parquet"
        base.mkdir(parents=True)
        (base / "not_a_partition").mkdir()
        (base / "class_uid=6003").mkdir()
        layer = DuckDBLayer(str(base))
        result = layer.get_available_partitions()
        assert 6003 in result
        assert len(result) == 1
        layer.close()

    def test_malformed_class_uid_skipped(self, tmp_path):
        base = tmp_path / "parquet"
        base.mkdir(parents=True)
        (base / "class_uid=notanint").mkdir()
        layer = DuckDBLayer(str(base))
        assert layer.get_available_partitions() == []
        layer.close()


# ==============================================================================
# TestClose
# ==============================================================================

class TestClose:

    def test_close_prevents_execute_query(self, tmp_path):
        layer = _make_layer(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.execute_query("SELECT 1", 6003)

    def test_close_prevents_query_partition(self, tmp_path):
        layer = _make_layer(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.query_partition(6003)

    def test_multiple_close_calls_safe(self, tmp_path):
        layer = _make_layer(tmp_path)
        layer.close()
        layer.close()
        layer.close()

    def test_close_sets_flag(self, tmp_path):
        layer = _make_layer(tmp_path)
        assert layer._closed is False
        layer.close()
        assert layer._closed is True