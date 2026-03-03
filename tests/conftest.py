# tests/conftest.py
# Shared pytest fixtures for all test modules.
# See header comment in each testX file for what it covers.

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
OCSF_SCHEMA_PATH = str(CONFIG_DIR / "ocsf_schema.json")
METRICS_PATH = str(CONFIG_DIR / "metrics.json")


@pytest.fixture(scope="session")
def ocsf_registry():
    from loghunter.schema.ocsf_field_registry import OCSFFieldRegistry
    return OCSFFieldRegistry(OCSF_SCHEMA_PATH)


@pytest.fixture(scope="session")
def metric_registry():
    from loghunter.schema.metric_registry import MetricRegistry
    return MetricRegistry(METRICS_PATH)


@pytest.fixture()
def sqlite_layer(tmp_path):
    from loghunter.engine.sqlite_layer import SQLiteLayer
    layer = SQLiteLayer(str(tmp_path / "test_metadata.db"))
    yield layer
    layer.close()


@pytest.fixture()
def audit_logger(sqlite_layer):
    from loghunter.audit.logger import AuditLogger
    return AuditLogger(sqlite_layer)


@pytest.fixture()
def tmp_parquet_path(tmp_path):
    parquet_dir = tmp_path / "logs.parquet"
    parquet_dir.mkdir()
    return str(parquet_dir)


@pytest.fixture()
def make_ocsf_event(ocsf_registry):
    from loghunter.schema.ocsf_event import OCSFEvent

    def _factory(
        class_uid: int = 6003,
        activity_id: int = 1,
        severity_id: int = 1,
        time: datetime | None = None,
        metadata_log_source: str = "test",
        metadata_original_time: str = "2026-01-01T00:00:00Z",
        **kwargs,
    ) -> OCSFEvent:
        return OCSFEvent(
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=severity_id,
            time=time or datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            metadata_log_source=metadata_log_source,
            metadata_original_time=metadata_original_time,
            registry=ocsf_registry,
            **kwargs,
        )

    return _factory
