# ==============================================================================
# tests/testEngine/testSqliteLayer.py
#
# Tests for loghunter/engine/sqlite_layer.py
#
# Coverage strategy — every branch explicitly targeted:
#
# Constructor:
#   None db_path → TypeError
#   Empty/whitespace → ValueError
#   Valid path → opens, creates tables, WAL mode
#   In-memory path (:memory:) → valid
#
# execute_write:
#   None sql → TypeError
#   None params → TypeError
#   SELECT statement → ValueError
#   SELECT with leading whitespace → ValueError
#   Valid INSERT → row written
#   Valid UPDATE → row updated
#   Valid DELETE → row deleted
#   Valid CREATE → table created
#   Called after close → RuntimeError
#
# execute_read:
#   None sql → TypeError
#   None params → TypeError
#   Non-SELECT statement (INSERT) → ValueError
#   Valid SELECT → list of dicts
#   Zero results → empty list
#   Called after close → RuntimeError
#
# close:
#   First call closes connection
#   Multiple calls are safe no-ops (idempotent)
#   execute_write after close → RuntimeError
#   execute_read after close → RuntimeError
#
# Schema:
#   All six required tables exist after construction
#   Tables are idempotent (CREATE IF NOT EXISTS)
# ==============================================================================

from __future__ import annotations

import pytest

from loghunter.engine.sqlite_layer import SQLiteLayer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make(tmp_path) -> SQLiteLayer:
    return SQLiteLayer(str(tmp_path / "test.db"))


# ==============================================================================
# TestConstructor
# ==============================================================================

class TestConstructor:

    def test_none_db_path_raises_type_error(self):
        with pytest.raises(TypeError):
            SQLiteLayer(None)

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            SQLiteLayer("")

    def test_whitespace_string_raises_value_error(self):
        with pytest.raises(ValueError):
            SQLiteLayer("   ")

    def test_valid_path_constructs_successfully(self, tmp_path):
        layer = SQLiteLayer(str(tmp_path / "test.db"))
        assert layer is not None
        layer.close()

    def test_in_memory_database_is_valid(self):
        layer = SQLiteLayer(":memory:")
        assert layer is not None
        layer.close()

    def test_creates_db_file_on_disk(self, tmp_path):
        db_path = tmp_path / "test.db"
        layer = SQLiteLayer(str(db_path))
        assert db_path.exists()
        layer.close()

    def test_wal_mode_enabled(self, tmp_path):
        layer = SQLiteLayer(str(tmp_path / "test.db"))
        rows = layer.execute_read("SELECT * FROM pragma_journal_mode()", ())
        # WAL mode should be set
        assert any("wal" in str(v).lower() for row in rows for v in row.values())
        layer.close()

    def test_all_required_tables_created(self, tmp_path):
        layer = _make(tmp_path)
        expected_tables = {
            "query_audit",
            "ingest_audit",
            "rule_audit",
            "rules",
            "baselines",
            "metric_snapshots",
        }
        rows = layer.execute_read(
            "SELECT name FROM sqlite_master WHERE type='table'", ()
        )
        created = {row["name"] for row in rows}
        assert expected_tables.issubset(created)
        layer.close()

    def test_construction_is_idempotent_second_connection(self, tmp_path):
        # Opening same db twice should not error (CREATE IF NOT EXISTS)
        path = str(tmp_path / "test.db")
        l1 = SQLiteLayer(path)
        l1.close()
        l2 = SQLiteLayer(path)
        l2.close()


# ==============================================================================
# TestExecuteWrite
# ==============================================================================

class TestExecuteWrite:

    def test_none_sql_raises_type_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(TypeError):
            layer.execute_write(None, ())
        layer.close()

    def test_none_params_raises_type_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(TypeError):
            layer.execute_write("INSERT INTO query_audit VALUES (1)", None)
        layer.close()

    def test_select_statement_raises_value_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(ValueError, match="SELECT"):
            layer.execute_write("SELECT * FROM query_audit", ())
        layer.close()

    def test_select_with_leading_whitespace_raises_value_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(ValueError, match="SELECT"):
            layer.execute_write("   SELECT * FROM query_audit", ())
        layer.close()

    def test_select_lowercase_raises_value_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(ValueError):
            layer.execute_write("select * from query_audit", ())
        layer.close()

    def test_insert_writes_row(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            """INSERT INTO query_audit
               (session_id, sql_template, event_class, success,
                row_count, latency_ms, failure_reason, executed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("sess1", "SELECT 1", 6003, 1, 10, 5.0, None, "2026-01-01T00:00:00Z")
        )
        rows = layer.execute_read(
            "SELECT * FROM query_audit WHERE session_id = ?", ("sess1",)
        )
        assert len(rows) == 1
        assert rows[0]["session_id"] == "sess1"
        layer.close()

    def test_update_modifies_row(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            """INSERT INTO baselines
               (entity_type, entity_value, metric_name, class_uid,
                mean, stddev, observation_count,
                window_start, window_end, computed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("user", "alice", "auth_count_per_hour", 6003,
             10.0, 2.0, 30,
             "2026-01-01T00:00:00Z", "2026-01-08T00:00:00Z",
             "2026-01-08T00:00:00Z")
        )
        layer.execute_write(
            "UPDATE baselines SET mean = ? WHERE entity_value = ?",
            (20.0, "alice")
        )
        rows = layer.execute_read(
            "SELECT mean FROM baselines WHERE entity_value = ?", ("alice",)
        )
        assert rows[0]["mean"] == 20.0
        layer.close()

    def test_delete_removes_row(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            """INSERT INTO metric_snapshots (snapshot_at, payload)
               VALUES (?, ?)""",
            ("2026-01-01T00:00:00Z", "{}")
        )
        layer.execute_write(
            "DELETE FROM metric_snapshots WHERE payload = ?", ("{}",)
        )
        rows = layer.execute_read("SELECT * FROM metric_snapshots", ())
        assert len(rows) == 0
        layer.close()

    def test_create_statement_is_permitted(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            "CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY)",
            ()
        )
        rows = layer.execute_read(
            "SELECT name FROM sqlite_master WHERE name='test_table'", ()
        )
        assert len(rows) == 1
        layer.close()

    def test_called_after_close_raises_runtime_error(self, tmp_path):
        layer = _make(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.execute_write(
                "INSERT INTO metric_snapshots (snapshot_at, payload) "
                "VALUES (?, ?)", ("2026-01-01", "{}")
            )

    def test_params_as_dict(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            """INSERT INTO metric_snapshots (snapshot_at, payload)
               VALUES (:ts, :payload)""",
            {"ts": "2026-01-01T00:00:00Z", "payload": "{}"}
        )
        rows = layer.execute_read("SELECT * FROM metric_snapshots", ())
        assert len(rows) == 1
        layer.close()


# ==============================================================================
# TestExecuteRead
# ==============================================================================

class TestExecuteRead:

    def test_none_sql_raises_type_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(TypeError):
            layer.execute_read(None, ())
        layer.close()

    def test_none_params_raises_type_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(TypeError):
            layer.execute_read("SELECT 1", None)
        layer.close()

    def test_non_select_raises_value_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(ValueError, match="SELECT"):
            layer.execute_read(
                "INSERT INTO metric_snapshots (snapshot_at, payload) "
                "VALUES (?, ?)", ("2026-01-01", "{}")
            )
        layer.close()

    def test_insert_as_read_raises_value_error(self, tmp_path):
        layer = _make(tmp_path)
        with pytest.raises(ValueError):
            layer.execute_read("INSERT INTO query_audit VALUES (1)", ())
        layer.close()

    def test_valid_select_returns_list_of_dicts(self, tmp_path):
        layer = _make(tmp_path)
        rows = layer.execute_read("SELECT * FROM query_audit", ())
        assert isinstance(rows, list)
        layer.close()

    def test_zero_results_returns_empty_list(self, tmp_path):
        layer = _make(tmp_path)
        rows = layer.execute_read(
            "SELECT * FROM query_audit WHERE session_id = ?",
            ("nonexistent",)
        )
        assert rows == []
        layer.close()

    def test_returns_correct_row_data(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            """INSERT INTO metric_snapshots (snapshot_at, payload)
               VALUES (?, ?)""",
            ("2026-01-01T00:00:00Z", '{"key": "value"}')
        )
        rows = layer.execute_read("SELECT * FROM metric_snapshots", ())
        assert len(rows) == 1
        assert rows[0]["payload"] == '{"key": "value"}'
        layer.close()

    def test_rows_are_dicts_not_tuples(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            "INSERT INTO metric_snapshots (snapshot_at, payload) VALUES (?,?)",
            ("2026-01-01", "{}")
        )
        rows = layer.execute_read("SELECT * FROM metric_snapshots", ())
        assert isinstance(rows[0], dict)
        layer.close()

    def test_multiple_rows_returned(self, tmp_path):
        layer = _make(tmp_path)
        for i in range(3):
            layer.execute_write(
                "INSERT INTO metric_snapshots (snapshot_at, payload) "
                "VALUES (?, ?)",
                (f"2026-01-0{i+1}", "{}")
            )
        rows = layer.execute_read("SELECT * FROM metric_snapshots", ())
        assert len(rows) == 3
        layer.close()

    def test_called_after_close_raises_runtime_error(self, tmp_path):
        layer = _make(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.execute_read("SELECT * FROM query_audit", ())

    def test_params_as_dict(self, tmp_path):
        layer = _make(tmp_path)
        layer.execute_write(
            "INSERT INTO metric_snapshots (snapshot_at, payload) "
            "VALUES (:ts, :payload)",
            {"ts": "2026-06-01", "payload": "{}"}
        )
        rows = layer.execute_read(
            "SELECT * FROM metric_snapshots WHERE snapshot_at = :ts",
            {"ts": "2026-06-01"}
        )
        assert len(rows) == 1
        layer.close()


# ==============================================================================
# TestClose
# ==============================================================================

class TestClose:

    def test_close_prevents_execute_write(self, tmp_path):
        layer = _make(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.execute_write(
                "INSERT INTO metric_snapshots (snapshot_at, payload) "
                "VALUES (?, ?)", ("2026-01-01", "{}")
            )

    def test_close_prevents_execute_read(self, tmp_path):
        layer = _make(tmp_path)
        layer.close()
        with pytest.raises(RuntimeError):
            layer.execute_read("SELECT * FROM metric_snapshots", ())

    def test_multiple_close_calls_are_safe(self, tmp_path):
        layer = _make(tmp_path)
        layer.close()
        layer.close()  # Must not raise
        layer.close()  # Must not raise

    def test_close_sets_closed_flag(self, tmp_path):
        layer = _make(tmp_path)
        assert layer._closed is False
        layer.close()
        assert layer._closed is True