# ==============================================================================
# tests/testIngest/testWriter.py
#
# Tests for loghunter/ingest/writer.py
#
# Coverage strategy — every branch explicitly targeted:
#
# Constructor:
#   None base_path → TypeError
#   Empty/whitespace base_path → ValueError
#   None audit_logger → TypeError
#   Valid → constructs
#
# write_batch:
#   None events → TypeError
#   Empty list → returns 0, logs ingest audit
#   Single class → partition dir created, part file written, count returned
#   Multiple classes → separate partition dirs
#   Sequential writes → incrementing part numbers
#   Calls audit_logger.log_ingest with correct counts
#
# write_replay_batch:
#   None events → TypeError
#   None session_id → TypeError
#   Empty session_id → ValueError
#   Empty events list → returns 0, dir still created
#   Valid → writes to replay.parquet/session_id=X/
#   Sequential writes → incrementing part numbers
#
# get_partition_path:
#   Returns correct path without creating directory
#
# _next_part_number:
#   Empty dir → 0
#   Existing parts → max + 1
#   Non-standard filenames → skipped gracefully
#
# _events_to_table:
#   Empty list → empty table
#   Events with datetime fields → serialised to ISO strings
#   Events with None values → preserved
# ==============================================================================

from __future__ import annotations

from datetime import datetime, timezone

import pyarrow.parquet as pq
import pytest

from loghunter.audit.logger import AuditLogger
from loghunter.engine.sqlite_layer import SQLiteLayer
from loghunter.exceptions import ReplaySessionNotFoundError
from loghunter.ingest.writer import ParquetWriter, _events_to_table, _next_part_number
from loghunter.schema.ocsf_event import OCSFEvent

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_layer(tmp_path):
    return SQLiteLayer(str(tmp_path / "meta.db"))


def _make_writer(tmp_path):
    layer = _make_layer(tmp_path)
    audit = AuditLogger(layer)
    writer = ParquetWriter(str(tmp_path / "parquet"), audit)
    return writer, layer


def _make_event(ocsf_registry, class_uid=6003, activity_id=1, severity_id=1):
    return OCSFEvent(
        class_uid=class_uid,
        activity_id=activity_id,
        severity_id=severity_id,
        time=T0,
        metadata_log_source="test",
        metadata_original_time="2026-01-01T00:00:00Z",
        registry=ocsf_registry,
    )


# ==============================================================================
# TestConstructor
# ==============================================================================

class TestConstructor:

    def test_none_base_path_raises_type_error(self, tmp_path, ocsf_registry):
        layer = _make_layer(tmp_path)
        with pytest.raises(TypeError, match="base_path"):
            ParquetWriter(None, AuditLogger(layer))
        layer.close()

    def test_empty_base_path_raises_value_error(self, tmp_path, ocsf_registry):
        layer = _make_layer(tmp_path)
        with pytest.raises(ValueError):
            ParquetWriter("", AuditLogger(layer))
        layer.close()

    def test_whitespace_base_path_raises_value_error(self, tmp_path, ocsf_registry):
        layer = _make_layer(tmp_path)
        with pytest.raises(ValueError):
            ParquetWriter("   ", AuditLogger(layer))
        layer.close()

    def test_none_audit_logger_raises_type_error(self, tmp_path):
        with pytest.raises(TypeError, match="audit_logger"):
            ParquetWriter(str(tmp_path / "p"), None)

    def test_valid_construction(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        assert writer is not None
        layer.close()


# ==============================================================================
# TestWriteBatch
# ==============================================================================

class TestWriteBatch:

    def test_none_events_raises_type_error(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        with pytest.raises(TypeError):
            writer.write_batch(None)
        layer.close()

    def test_empty_list_returns_zero(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        assert writer.write_batch([]) == 0
        layer.close()

    def test_empty_list_logs_ingest_audit(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        writer.write_batch([], source_format="zeek_conn")
        rows = layer.execute_read("SELECT * FROM ingest_audit", ())
        assert len(rows) == 1
        assert rows[0]["event_count"] == 0
        layer.close()

    def test_single_event_returns_one(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry)]
        count = writer.write_batch(events)
        assert count == 1
        layer.close()

    def test_partition_dir_created(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry, class_uid=6003)]
        writer.write_batch(events)
        assert (tmp_path / "parquet" / "class_uid=6003").exists()
        layer.close()

    def test_part_file_written(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry)]
        writer.write_batch(events)
        part_dir = tmp_path / "parquet" / "class_uid=6003"
        parts = list(part_dir.glob("part-*.parquet"))
        assert len(parts) == 1
        layer.close()

    def test_parquet_file_is_readable(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry)]
        writer.write_batch(events)
        part_dir = tmp_path / "parquet" / "class_uid=6003"
        part_file = list(part_dir.glob("part-*.parquet"))[0]
        table = pq.read_table(str(part_file))
        assert table.num_rows == 1
        layer.close()

    def test_multiple_events_same_class(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry) for _ in range(5)]
        count = writer.write_batch(events)
        assert count == 5
        layer.close()

    def test_multiple_classes_separate_partitions(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [
            _make_event(ocsf_registry, class_uid=6003),
            _make_event(ocsf_registry, class_uid=3001),
        ]
        count = writer.write_batch(events)
        assert count == 2
        assert (tmp_path / "parquet" / "class_uid=6003").exists()
        assert (tmp_path / "parquet" / "class_uid=3001").exists()
        layer.close()

    def test_sequential_writes_increment_part_number(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry)]
        writer.write_batch(events)
        writer.write_batch(events)
        part_dir = tmp_path / "parquet" / "class_uid=6003"
        parts = sorted(part_dir.glob("part-*.parquet"))
        assert len(parts) == 2
        assert parts[0].name == "part-0000.parquet"
        assert parts[1].name == "part-0001.parquet"
        layer.close()

    def test_audit_logged_with_correct_count(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry) for _ in range(4)]
        writer.write_batch(events, source_format="evtx", file_path="/logs/sec.evtx")
        rows = layer.execute_read("SELECT * FROM ingest_audit", ())
        assert rows[0]["event_count"] == 4
        assert rows[0]["source_format"] == "evtx"
        assert rows[0]["file_path"] == "/logs/sec.evtx"
        layer.close()

    def test_audit_failed_count_zero_on_success(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        writer.write_batch([_make_event(ocsf_registry)])
        rows = layer.execute_read("SELECT * FROM ingest_audit", ())
        assert rows[0]["failed_count"] == 0
        layer.close()


# ==============================================================================
# TestWriteReplayBatch
# ==============================================================================

class TestWriteReplayBatch:

    def test_none_events_raises_type_error(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        with pytest.raises(TypeError):
            writer.write_replay_batch(None, "session-1")
        layer.close()

    def test_none_session_id_raises_type_error(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        with pytest.raises(TypeError):
            writer.write_replay_batch([], None)
        layer.close()

    def test_empty_session_id_raises_value_error(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        with pytest.raises(ValueError):
            writer.write_replay_batch([], "")
        layer.close()

    def test_whitespace_session_id_raises_value_error(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        with pytest.raises(ValueError):
            writer.write_replay_batch([], "   ")
        layer.close()

    def test_empty_events_returns_zero(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        count = writer.write_replay_batch([], "session-abc")
        assert count == 0
        layer.close()

    def test_empty_events_still_creates_dir(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        writer.write_replay_batch([], "session-xyz")
        replay_dir = tmp_path / "parquet" / "replay.parquet" / "session_id=session-xyz"
        assert replay_dir.exists()
        layer.close()

    def test_valid_write_returns_count(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry) for _ in range(3)]
        count = writer.write_replay_batch(events, "sess-001")
        assert count == 3
        layer.close()

    def test_replay_partition_path_correct(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry)]
        writer.write_replay_batch(events, "sess-001")
        replay_dir = tmp_path / "parquet" / "replay.parquet" / "session_id=sess-001"
        parts = list(replay_dir.glob("part-*.parquet"))
        assert len(parts) == 1
        layer.close()

    def test_sequential_replay_writes_increment_parts(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry)]
        writer.write_replay_batch(events, "sess-seq")
        writer.write_replay_batch(events, "sess-seq")
        replay_dir = tmp_path / "parquet" / "replay.parquet" / "session_id=sess-seq"
        parts = sorted(replay_dir.glob("part-*.parquet"))
        assert len(parts) == 2
        layer.close()

    def test_different_sessions_isolated(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        events = [_make_event(ocsf_registry)]
        writer.write_replay_batch(events, "sess-a")
        writer.write_replay_batch(events, "sess-b")
        dir_a = tmp_path / "parquet" / "replay.parquet" / "session_id=sess-a"
        dir_b = tmp_path / "parquet" / "replay.parquet" / "session_id=sess-b"
        assert len(list(dir_a.glob("*.parquet"))) == 1
        assert len(list(dir_b.glob("*.parquet"))) == 1
        layer.close()


# ==============================================================================
# TestGetPartitionPath
# ==============================================================================

class TestGetPartitionPath:

    def test_returns_correct_path(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        path = writer.get_partition_path(6003)
        assert path == tmp_path / "parquet" / "class_uid=6003"
        layer.close()

    def test_does_not_create_directory(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        path = writer.get_partition_path(6003)
        assert not path.exists()
        layer.close()

    def test_different_class_uids_different_paths(self, tmp_path, ocsf_registry):
        writer, layer = _make_writer(tmp_path)
        p1 = writer.get_partition_path(6003)
        p2 = writer.get_partition_path(3001)
        assert p1 != p2
        layer.close()


# ==============================================================================
# TestNextPartNumber
# ==============================================================================

class TestNextPartNumber:

    def test_empty_dir_returns_zero(self, tmp_path):
        d = tmp_path / "parts"
        d.mkdir()
        assert _next_part_number(d) == 0

    def test_existing_parts_returns_max_plus_one(self, tmp_path):
        d = tmp_path / "parts"
        d.mkdir()
        (d / "part-0000.parquet").touch()
        (d / "part-0001.parquet").touch()
        assert _next_part_number(d) == 2

    def test_non_standard_filenames_skipped(self, tmp_path):
        d = tmp_path / "parts"
        d.mkdir()
        (d / "part-0000.parquet").touch()
        (d / "_metadata").touch()
        (d / "not-a-part.parquet").touch()
        assert _next_part_number(d) == 1


# ==============================================================================
# TestEventsToTable
# ==============================================================================

class TestEventsToTable:

    def test_empty_list_returns_empty_table(self):
        table = _events_to_table([])
        assert table.num_rows == 0

    def test_single_event_correct_row_count(self, ocsf_registry):
        events = [_make_event(ocsf_registry)]
        table = _events_to_table(events)
        assert table.num_rows == 1

    def test_datetime_serialised_to_string(self, ocsf_registry):
        events = [_make_event(ocsf_registry)]
        table = _events_to_table(events)
        time_col = table.column("time")
        val = time_col[0].as_py()
        assert isinstance(val, str)
        assert "2026" in val

    def test_multiple_events_correct_row_count(self, ocsf_registry):
        events = [_make_event(ocsf_registry) for _ in range(5)]
        table = _events_to_table(events)
        assert table.num_rows == 5


    def test_part_with_non_numeric_suffix_skipped(self, tmp_path):
        d = tmp_path / "parts"
        d.mkdir()
        (d / "part-0000.parquet").touch()
        (d / "part-abc.parquet").touch()  # triggers ValueError in int()
        assert _next_part_number(d) == 1

    def test_replay_os_error_raises_replay_session_not_found(
        self, tmp_path, ocsf_registry
    ):
        writer, layer = _make_writer(tmp_path)
        # Place a FILE at the replay.parquet path to block mkdir
        replay_base = tmp_path / "parquet" / "replay.parquet"
        replay_base.parent.mkdir(parents=True, exist_ok=True)
        replay_base.touch()  # file, not dir — mkdir will raise OSError
        from loghunter.exceptions import ReplaySessionNotFoundError
        with pytest.raises(ReplaySessionNotFoundError):
            writer.write_replay_batch([_make_event(ocsf_registry)], "sess-err")
        layer.close()