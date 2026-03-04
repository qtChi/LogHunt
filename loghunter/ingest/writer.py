# ==============================================================================
# loghunter/ingest/writer.py
#
# ParquetWriter — writes OCSFEvent batches to partitioned Parquet.
#
# Per spec section 4.3:
#   - Uses pyarrow directly — NOT through DuckDB.
#   - Partition path: {base_path}/class_uid={uid}/part-NNNN.parquet
#   - Replay path:   {base_path}/replay.parquet/session_id={id}/
#   - Calls audit_logger.log_ingest() after each write.
#   - write_batch returns count of events written.
#   - Raises ReplaySessionNotFoundError on invalid replay session path.
#
# Build Priority: Phase 1
# ==============================================================================

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from loghunter.audit.logger import AuditLogger
from loghunter.exceptions import ReplaySessionNotFoundError
from loghunter.schema.audit_models import IngestAuditEntry
from loghunter.schema.ocsf_event import OCSFEvent


def _events_to_table(events: list[OCSFEvent]) -> pa.Table:
    """Convert a list of OCSFEvent to a pyarrow Table."""
    if not events:
        return pa.table({})

    # Collect all field names across all events
    all_keys: list[str] = []
    seen: set[str] = set()
    for event in events:
        for k in event.to_dict():
            if k not in seen:
                all_keys.append(k)
                seen.add(k)

    columns: dict[str, list[Any]] = {k: [] for k in all_keys}
    for event in events:
        d = event.to_dict()
        for k in all_keys:
            columns[k].append(d.get(k))

    # Convert datetime columns to strings for Parquet compatibility
    for k, vals in columns.items():
        columns[k] = [
            v.isoformat() if hasattr(v, "isoformat") else v
            for v in vals
        ]

    return pa.table(columns)


def _next_part_number(partition_dir: Path) -> int:
    """Return the next sequential part file number for a partition."""
    existing = list(partition_dir.glob("part-*.parquet"))
    if not existing:
        return 0
    numbers = []
    for p in existing:
        try:
            numbers.append(int(p.stem.split("-")[1]))
        except (IndexError, ValueError):
            pass
    return max(numbers) + 1 if numbers else 0


class ParquetWriter:
    """
    Writes OCSFEvent batches to partitioned Parquet files.

    Per spec section 4.3.
    """

    def __init__(self, base_path: str, audit_logger: AuditLogger) -> None:
        """
        Args:
            base_path:    Root path for Parquet partitions (PARQUET_BASE_PATH).
            audit_logger: Initialised AuditLogger.

        Raises:
            TypeError:  If any argument is None.
            ValueError: If base_path is empty or whitespace.
        """
        if base_path is None:
            raise TypeError("base_path must not be None")
        if not str(base_path).strip():
            raise ValueError("base_path must not be empty or whitespace")
        if audit_logger is None:
            raise TypeError("audit_logger must not be None")

        self._base_path = Path(base_path)
        self._audit = audit_logger

    def write_batch(
        self,
        events: list[OCSFEvent],
        source_format: str = "unknown",
        file_path: str | None = None,
    ) -> int:
        """
        Write a batch of OCSFEvent objects to partitioned Parquet.

        Events are grouped by class_uid. Each class_uid gets its own
        partition directory. A new part file is appended per call.

        Args:
            events:        List of OCSFEvent objects. Empty list is valid.
            source_format: Parser format string for audit logging.
            file_path:     Source file path for audit logging.

        Returns:
            Count of events written.

        Raises:
            TypeError: If events is None.
        """
        if events is None:
            raise TypeError("events must not be None")

        if not events:
            self._log_ingest(source_format, 0, 0, file_path)
            return 0

        # Group by class_uid
        by_class: dict[int, list[OCSFEvent]] = {}
        for event in events:
            uid = event.get_class_uid()
            by_class.setdefault(uid, []).append(event)

        written = 0
        for class_uid, class_events in by_class.items():
            partition_dir = self.get_partition_path(class_uid)
            partition_dir.mkdir(parents=True, exist_ok=True)

            part_num = _next_part_number(partition_dir)
            out_path = partition_dir / f"part-{part_num:04d}.parquet"

            table = _events_to_table(class_events)
            pq.write_table(table, str(out_path))
            written += len(class_events)

        self._log_ingest(source_format, written, 0, file_path)
        return written

    def write_replay_batch(
        self,
        events: list[OCSFEvent],
        session_id: str,
        source_format: str = "replay",
    ) -> int:
        """
        Write events to a replay session partition.

        Path: {base_path}/replay.parquet/session_id={session_id}/

        Args:
            events:     List of OCSFEvent objects.
            session_id: Replay session identifier.
            source_format: For audit logging.

        Returns:
            Count of events written.

        Raises:
            TypeError:                  If events or session_id is None.
            ValueError:                 If session_id is empty.
            ReplaySessionNotFoundError: If the replay base path cannot
                                        be created (OS error).
        """
        if events is None:
            raise TypeError("events must not be None")
        if session_id is None:
            raise TypeError("session_id must not be None")
        if not str(session_id).strip():
            raise ValueError("session_id must not be empty or whitespace")

        replay_dir = self._base_path / "replay.parquet" / f"session_id={session_id}"
        try:
            replay_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReplaySessionNotFoundError(
                f"Cannot create replay session directory: {replay_dir}: {exc}"
            ) from exc

        if not events:
            return 0

        part_num = _next_part_number(replay_dir)
        out_path = replay_dir / f"part-{part_num:04d}.parquet"
        table = _events_to_table(events)
        pq.write_table(table, str(out_path))
        return len(events)

    def get_partition_path(self, class_uid: int) -> Path:
        """
        Return the partition directory path for a given class_uid.

        Does not create the directory.

        Args:
            class_uid: OCSF event class identifier.

        Returns:
            Path object for the partition directory.
        """
        return self._base_path / f"class_uid={class_uid}"

    def _log_ingest(
        self,
        source_format: str,
        event_count: int,
        failed_count: int,
        file_path: str | None,
    ) -> None:
        self._audit.log_ingest(
            IngestAuditEntry(
                ingest_id=str(uuid.uuid4()),
                source_format=source_format,
                event_count=event_count,
                failed_count=failed_count,
                file_path=file_path,
            )
        )