# LogHunt — Detection Engineering Workbench
## Living Specification v2.0
### Last Updated: Phase 1 — 14 of 17 files complete

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Layout](#2-repository-layout)
3. [Technology Stack](#3-technology-stack)
4. [Storage Architecture](#4-storage-architecture)
5. [OCSF Event Classes](#5-ocsf-event-classes)
6. [Schema Layer — COMPLETED](#6-schema-layer)
7. [Configuration — COMPLETED](#7-configuration)
8. [Ingest Layer — PARTIALLY COMPLETE](#8-ingest-layer)
9. [Engine Layer — PARTIALLY COMPLETE](#9-engine-layer)
10. [Audit Layer — COMPLETED](#10-audit-layer)
11. [LLM Layer — NOT STARTED](#11-llm-layer)
12. [UI Layer — NOT STARTED](#12-ui-layer)
13. [Test Coverage Summary](#13-test-coverage-summary)
14. [Architectural Decisions (DECISIONS.md)](#14-architectural-decisions)
15. [Phase Build Order](#15-phase-build-order)
16. [CI/CD](#16-cicd)

---

## 1. Project Overview

LogHunt is a local detection engineering workbench for SOC analyst portfolio demonstration. It implements:

- **OCSF normalisation** of raw logs from Zeek, Windows EVTX, Syslog, and Apache formats
- **Behavioral baselining** using statistical models per entity per metric
- **Sigma rule management** with LLM-assisted draft generation and analyst confirmation workflow
- **MITRE ATT&CK coverage analysis** from deterministic pattern rules
- **Replay engine** for testing rules against historical sessions
- **Streamlit UI** with tabs for each capability

All data lives locally. No cloud dependencies. Ollama provides local LLM inference.

---

## 2. Repository Layout

```
LogHunt/
├── .env                          # Not committed — loaded by config.py
├── .env.example                  # Template
├── .gitignore
├── pyproject.toml                # pytest + coverage config
├── requirements.txt              # Runtime deps
├── requirements-dev.txt          # Test/dev deps
├── DECISIONS.md                  # 12 documented judgment decisions
├── LOGHUNT_SPEC.md               # This file
│
├── config/
│   ├── ocsf_schema.json          # OCSF field registry (60+ fields)
│   └── metrics.json              # 9 built-in metric definitions
│
├── data/
│   ├── logs.parquet/             # Partitioned by class_uid=X/
│   │   └── class_uid=6003/
│   ├── replay.parquet/           # Partitioned by session_id=X/
│   └── metadata.db               # SQLite — all mutable application state
│
├── rules/
│   ├── confirmed/                # Exported confirmed Sigma YAML
│   └── drafts/                   # LLM-generated draft YAML
│
├── iocs/                         # IOC flat files
│
├── scripts/
│   ├── ingest_sample.py
│   ├── run_baseline.py
│   └── export_rules.py
│
├── loghunter/
│   ├── __init__.py
│   ├── config.py                 # ✅ COMPLETE
│   ├── exceptions.py             # ✅ COMPLETE
│   │
│   ├── schema/
│   │   ├── __init__.py
│   │   ├── ocsf_field_registry.py   # ✅ COMPLETE — 100% coverage
│   │   ├── ocsf_event.py            # ✅ COMPLETE — 100% coverage
│   │   ├── metric_registry.py       # ✅ COMPLETE — 100% coverage
│   │   └── audit_models.py          # ✅ COMPLETE — 100% coverage
│   │
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── normalizer.py            # 🔲 NEXT — Phase 1
│   │   ├── writer.py                # 🔲 Phase 1
│   │   └── parsers/
│   │       ├── __init__.py
│   │       ├── base.py              # ✅ COMPLETE — 100% coverage
│   │       ├── zeek.py              # ✅ COMPLETE — 100% coverage
│   │       ├── evtx.py              # ✅ COMPLETE — 100% coverage
│   │       ├── syslog.py            # ✅ COMPLETE — 100% coverage
│   │       └── apache.py            # ✅ COMPLETE — 100% coverage
│   │
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── sqlite_layer.py          # ✅ COMPLETE — 100% coverage
│   │   ├── duckdb_layer.py          # 🔲 Phase 1
│   │   ├── query_builder.py         # 🔲 Phase 2
│   │   ├── baseline.py              # 🔲 Phase 2
│   │   ├── anomaly.py               # 🔲 Phase 2
│   │   ├── sigma_engine.py          # 🔲 Phase 2
│   │   ├── replay_engine.py         # 🔲 Phase 2
│   │   ├── ioc_matcher.py           # 🔲 Phase 2
│   │   └── mitre_mapper.py          # ✅ COMPLETE — 100% coverage
│   │
│   ├── audit/
│   │   ├── __init__.py
│   │   └── logger.py                # ✅ COMPLETE — 100% coverage
│   │
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── anomaly_explainer.py     # 🔲 Phase 2
│   │   └── sigma_draft_generator.py # 🔲 Phase 2
│   │
│   └── ui/
│       ├── __init__.py
│       ├── app.py                   # 🔲 Phase 3
│       ├── tabs/
│       │   ├── ingest_tab.py        # 🔲 Phase 3
│       │   ├── query_tab.py         # 🔲 Phase 3
│       │   ├── baseline_tab.py      # 🔲 Phase 3
│       │   ├── sigma_tab.py         # 🔲 Phase 3
│       │   ├── replay_tab.py        # 🔲 Phase 3
│       │   └── coverage_tab.py      # 🔲 Phase 3
│       └── components/
│           ├── event_table.py       # 🔲 Phase 3
│           ├── anomaly_card.py      # 🔲 Phase 3
│           └── coverage_matrix.py   # 🔲 Phase 3
│
└── tests/
    ├── conftest.py                  # Shared fixtures
    ├── testConfig.py
    ├── testExceptions.py
    ├── testSchema/
    │   ├── testOcsfFieldRegistry.py  # ✅ 100 tests — 100% coverage
    │   ├── testOcsfEvent.py          # ✅ ~80 tests — 100% coverage
    │   ├── testMetricRegistry.py     # ✅ ~70 tests — 100% coverage
    │   └── testAuditModels.py        # ✅ ~30 tests — 100% coverage
    ├── testIngest/
    │   ├── testNormalizer.py         # 🔲 NEXT
    │   ├── testWriter.py             # 🔲 Phase 1
    │   └── testParsers/
    │       ├── testBase.py           # ✅ 100% coverage
    │       ├── testZeek.py           # ✅ 100% coverage
    │       ├── testEvtx.py           # ✅ 100% coverage
    │       ├── testSyslog.py         # ✅ 100% coverage
    │       └── testApache.py         # ✅ 100% coverage
    ├── testEngine/
    │   ├── testSqliteLayer.py        # ✅ 100% coverage
    │   ├── testDuckdbLayer.py        # 🔲 Phase 1
    │   ├── testQueryBuilder.py       # 🔲 Phase 2
    │   ├── testBaseline.py           # 🔲 Phase 2
    │   ├── testAnomaly.py            # 🔲 Phase 2
    │   ├── testSigmaEngine.py        # 🔲 Phase 2
    │   ├── testReplayEngine.py       # 🔲 Phase 2
    │   ├── testIocMatcher.py         # 🔲 Phase 2
    │   └── testMitreMapper.py        # ✅ 100% coverage
    ├── testLlm/
    │   ├── testAnomalyExplainer.py   # 🔲 Phase 2
    │   └── testSigmaDraftGenerator.py # 🔲 Phase 2
    ├── testAudit/
    │   └── testLogger.py             # ✅ 100% coverage
    ├── integration/
    └── security/
```

---

## 3. Technology Stack

### Runtime (requirements.txt)
```
python-dotenv==1.0.1
python-evtx==0.8.0
pandas==2.2.3
pyarrow==15.0.2
duckdb==0.10.3
pydantic==2.7.4
instructor==1.3.3
ollama==0.2.1
streamlit==1.35.0
pysigma==0.10.10
ruamel.yaml==0.18.6
numpy==1.26.4
scipy==1.13.1
```

### Dev (requirements-dev.txt)
```
pytest==8.2.2
pytest-cov==5.0.0
pytest-mock==3.14.0
hypothesis==6.103.4
coverage==7.5.3
```

---

## 4. Storage Architecture

### 4.1 DuckDB — Read-Only Analytical Layer
- Opened with `read_only=True` at the driver level
- Scans Parquet partitions under `{PARQUET_BASE_PATH}/class_uid={uid}/`
- **Never writes** — DuckDB cannot modify Parquet data
- Replay partitions at `{PARQUET_BASE_PATH}/replay.parquet/session_id={id}/`
- `QueryBuilder.execute` hardcoded `include_replay=False` — not configurable

### 4.2 SQLite — Mutable Application State
- All mutable state: audit logs, baselines, rule store, metric snapshots
- WAL mode enabled on connection
- Accessed exclusively through `SQLiteLayer`
- Tables: `query_audit`, `ingest_audit`, `rule_audit`, `rules`, `baselines`, `metric_snapshots`

### 4.3 Parquet — Event Storage
- Written by `ParquetWriter` via `pyarrow` directly (not through DuckDB)
- Partitioned: `data/logs.parquet/class_uid={uid}/part-NNNN.parquet`
- Replay isolated: `data/replay.parquet/session_id={id}/`

### 4.4 Storage Boundary Rule
| Operation | Storage | Access Class |
|---|---|---|
| Write events | Parquet | `ParquetWriter` |
| Read events (analytics) | DuckDB → Parquet | `DuckDBLayer` |
| All application state | SQLite | `SQLiteLayer` |
| Audit log | SQLite | `AuditLogger` |

---

## 5. OCSF Event Classes

| class_uid | Name | Source Format |
|---|---|---|
| 1001 | File System Activity | Syslog, EVTX |
| 3001 | Network Activity | Zeek conn.log |
| 3002 | HTTP Activity | Apache access log |
| 4001 | Process Activity | EVTX (Sysmon) |
| 6003 | Authentication Activity | EVTX Security log |

---

## 6. Schema Layer

### 6.1 `loghunter/exceptions.py` ✅ COMPLETE — 100% coverage

```python
class LogHuntError(Exception):
    """Base class for all LogHunt application exceptions."""

class SchemaError(LogHuntError): ...
class UnknownFieldError(SchemaError, ValueError): ...
class UnsupportedClassError(SchemaError, ValueError): ...

class StorageError(LogHuntError): ...
class PartitionNotFoundError(StorageError, ValueError): ...
class ReplaySessionNotFoundError(StorageError, ValueError): ...

class RegistrationError(LogHuntError): ...
class UnregisteredFormatError(RegistrationError, ValueError): ...

class RuleError(LogHuntError): ...
class RuleNotFoundError(RuleError, ValueError): ...
class RuleNotConfirmedError(RuleError, ValueError): ...
```

**Design rationale:** All exceptions subclass their closest built-in so broad `except ValueError` blocks still work. Tests assert on specific types. UI catches specific types to surface meaningful messages.

---

### 6.2 `loghunter/schema/ocsf_field_registry.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testSchema/testOcsfFieldRegistry.py` — 100 tests

```python
SUPPORTED_CLASSES: frozenset[int] = frozenset({1001, 3001, 3002, 4001, 6003})

@dataclass(frozen=True)
class FieldDefinition:
    field_path: str
    field_type: str           # "VARCHAR", "INTEGER", "TIMESTAMP", "VARCHAR[]"
    required: bool
    applicable_classes: tuple[int, ...]
    description: str
    source_examples: tuple[str, ...]

class OCSFFieldRegistry:
    def __init__(self, schema_path: str) -> None:
        """
        Load OCSF field schema from JSON.
        Raises TypeError if None, ValueError if empty/whitespace,
        FileNotFoundError if missing, ValueError if malformed.
        Duplicate field_path entries: applicable_classes merged,
        required=True wins, source_examples deduplicated.
        """

    def get_field_definition(self, field_path: str) -> Optional[FieldDefinition]:
        """Returns FieldDefinition or None. Never raises."""

    def get_fields_for_class(self, class_uid: int) -> list[FieldDefinition]:
        """
        Returns all fields for class. Returns copy not internal ref.
        Raises UnsupportedClassError for unknown class_uid.
        """

    def get_required_fields(self, class_uid: int) -> list[str]:
        """
        Returns dot-notation paths of required fields.
        Raises UnsupportedClassError for unknown class_uid.
        """

    def is_valid_field(self, field_path: str, class_uid: int) -> bool:
        """
        Returns True only if field registered AND class in applicable_classes.
        Never raises — None inputs return False.
        """

    def get_field_type(self, field_path: str) -> Optional[str]:
        """Returns type string or None. Never raises."""

    @property
    def schema_version(self) -> str: ...
```

**Universal required fields (all 5 classes):**
`class_uid`, `activity_id`, `severity_id`, `time`, `metadata.log_source`, `metadata.original_time`

---

### 6.3 `loghunter/schema/ocsf_event.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testSchema/testOcsfEvent.py` — ~80 tests

```python
class OCSFEvent:
    def __init__(
        self,
        class_uid: int,           # Must be in SUPPORTED_CLASSES
        activity_id: int,         # Non-negative, not bool
        severity_id: int,         # 0–6 inclusive, not bool
        time: datetime,           # Timezone-aware
        metadata_log_source: str, # Non-empty, non-whitespace
        metadata_original_time: str, # Non-empty, non-whitespace
        registry: OCSFFieldRegistry,
        **kwargs: Any,            # Unknown fields → UnknownFieldError
    ) -> None: ...

    def to_dict(self) -> dict[str, Any]:
        """Flat dict of all fields. None values included. Returns copy."""

    def get_field(self, field_path: str) -> Any:
        """
        Returns field value or None if unset.
        Raises TypeError if None path, ValueError if not registered for class.
        """

    def set_field(self, field_path: str, value: Any) -> None:
        """
        Post-construction field setter. Used by OCSFNormalizer for
        derived fields (e.g. mitre_technique_ids).
        Raises TypeError if None path, ValueError if not registered.
        """

    def validate(self) -> list[str]:
        """
        Never raises. Returns list of error strings.
        Checks: required fields not None, severity_id 0-6,
        time timezone-aware, IP fields valid IPv4/IPv6,
        port fields in 0-65535.
        """

    def get_class_uid(self) -> int: ...
    def get_time(self) -> datetime: ...

    def __eq__(self, other: object) -> bool:
        """Equal on: class_uid, time, metadata.log_source, metadata.original_time"""

    def __hash__(self) -> int:
        """Hash of same four identity fields."""

    def __repr__(self) -> str:
        """OCSFEvent(class_uid=6003, source=evtx, time=2026-01-01T00:00:00Z)"""
```

---

### 6.4 `loghunter/schema/metric_registry.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testSchema/testMetricRegistry.py` — ~70 tests

```python
SUPPORTED_COMPUTATIONS: frozenset[str] = frozenset({
    "count", "distinct_field_count", "sum_field", "rate_per_hour"
})

@dataclass(frozen=True)
class MetricDefinition:
    metric_name: str
    class_uid: int
    entity_type: str      # "user", "ip", "process", "host"
    entity_field: str     # OCSF field path for grouping
    computation: str      # One of SUPPORTED_COMPUTATIONS
    target_field: Optional[str]  # For distinct_field_count and sum_field
    description: str

class MetricRegistry:
    def __init__(self, metrics_path: str) -> None:
        """
        Load from metrics.json.
        Raises TypeError (None), ValueError (empty/malformed/duplicate/
        unsupported computation), FileNotFoundError (missing).
        Duplicate (metric_name, class_uid) pair → ValueError.
        """

    def get_metric(self, metric_name: str, class_uid: int) -> Optional[MetricDefinition]:
        """Returns MetricDefinition or None. Never raises."""

    def get_metrics_for_class(self, class_uid: int) -> list[MetricDefinition]:
        """
        Returns copy of metrics list.
        Raises UnsupportedClassError for unknown class_uid.
        Empty list for classes with no metrics defined.
        """

    def compute_current_value(
        self, metric_name: str, class_uid: int, events: list[OCSFEvent]
    ) -> Optional[float]:
        """
        Dispatches to computation handler based on MetricDefinition.computation.
        Returns None for empty events list.
        Raises TypeError if events is None.
        Raises ValueError if metric not registered.
        """
```

**Computation handlers (pure functions, independently testable):**
- `_compute_count(events, target_field) → float` — `len(events)`
- `_compute_distinct_field_count(events, target_field) → Optional[float]` — distinct non-None values
- `_compute_sum_field(events, target_field) → Optional[float]` — sum, skips non-numeric
- `_compute_rate_per_hour(events, target_field) → Optional[float]` — None if <2 events or zero span

**Built-in metrics (9 total):**
| metric_name | class_uid | computation |
|---|---|---|
| auth_count_per_hour | 6003 | rate_per_hour |
| auth_distinct_src_ips | 6003 | distinct_field_count |
| login_attempt_count | 6003 | count |
| process_exec_count | 4001 | count |
| process_distinct_names | 4001 | distinct_field_count |
| child_process_spawn_rate | 4001 | rate_per_hour |
| net_connection_count_per_hour | 3001 | rate_per_hour |
| net_distinct_dst_ports | 3001 | distinct_field_count |
| net_bytes_out_per_hour | 3001 | sum_field |

---

### 6.5 `loghunter/schema/audit_models.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testSchema/testAuditModels.py` — ~30 tests

```python
def _now_utc() -> str:
    """Returns current UTC time as %Y-%m-%dT%H:%M:%SZ string."""

@dataclass  # mutable — AuditLogger populates fields post-construction
class QueryAuditEntry:
    session_id: str
    sql_template: str
    event_class: Optional[int] = None
    success: bool = True
    row_count: Optional[int] = None
    latency_ms: Optional[float] = None
    failure_reason: Optional[str] = None
    executed_at: str = field(default_factory=_now_utc)

@dataclass
class IngestAuditEntry:
    ingest_id: str
    source_format: str
    event_count: int = 0
    failed_count: int = 0
    file_path: Optional[str] = None
    ingested_at: str = field(default_factory=_now_utc)

@dataclass
class RuleAuditEntry:
    rule_id: str
    event_type: str   # created|confirmed|updated|exported|backtested|deleted
    session_id: Optional[str] = None
    detail: Optional[str] = None
    occurred_at: str = field(default_factory=_now_utc)
```

---

## 7. Configuration

### 7.1 `loghunter/config.py` ✅ COMPLETE

```python
# Loaded from .env at project root via python-dotenv
OLLAMA_HOST: str    # default: "http://localhost:11434"
LLM_MODEL: str      # default: "llama3"
PARQUET_BASE_PATH: str  # default: "./data/logs.parquet"
METADATA_DB_PATH: str   # default: "./data/metadata.db"
LOG_LEVEL: int      # default: logging.INFO
```

No component reads `os.environ` directly — all import from `config.py`.

### 7.2 `.env.example`
```
OLLAMA_HOST=http://localhost:11434
LLM_MODEL=llama3
PARQUET_BASE_PATH=./data/logs.parquet
METADATA_DB_PATH=./data/metadata.db
LOG_LEVEL=INFO
```

---

## 8. Ingest Layer

### 8.1 `loghunter/ingest/parsers/base.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testIngest/testParsers/testBase.py`

```python
class LogParser(ABC):
    @property
    @abstractmethod
    def source_format(self) -> str:
        """Identifier e.g. "zeek_conn", "evtx", "syslog", "apache_access"."""

    @abstractmethod
    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Parse single raw line. Returns dict or None.
        Never raises — bad lines return None.
        """

    def parse_batch(self, raw_lines: list[str]) -> tuple[list[dict], list[str]]:
        """
        Calls parse() per line. Exceptions caught → treated as None.
        Returns (successes, failures).
        Raises TypeError if raw_lines is None.
        """
```

---

### 8.2 `loghunter/ingest/parsers/zeek.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testIngest/testParsers/testZeek.py`

```python
class ZeekParser(LogParser):
    """Parses Zeek TSV conn.log format."""
    source_format = "zeek_conn"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Returns None for: None, blank, '#' comments.
        '#fields' header updates self._fields for dynamic column detection.
        '-' values stored as None.
        Wrong field count → None.
        """
```

---

### 8.3 `loghunter/ingest/parsers/evtx.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testIngest/testParsers/testEvtx.py`

```python
class EVTXParser(LogParser):
    """Parses Windows EVTX XML record strings."""
    source_format = "evtx"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Returns None for: None, blank, invalid XML, missing System,
        missing EventID.
        Extracts: EventID, TimeCreated, Computer, Channel,
        and all named EventData/Data elements.
        Data elements without Name attribute are skipped.
        """
```

---

### 8.4 `loghunter/ingest/parsers/syslog.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testIngest/testParsers/testSyslog.py`

```python
class SyslogParser(LogParser):
    """Parses RFC 3164 syslog lines."""
    source_format = "syslog"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Returns None for: None, blank, non-matching lines.
        Fields: priority (None if absent), month, day, time,
        hostname, process, pid (None if absent), message.
        """
```

---

### 8.5 `loghunter/ingest/parsers/apache.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testIngest/testParsers/testApache.py`

```python
class ApacheParser(LogParser):
    """Parses Apache Combined Log Format access log lines."""
    source_format = "apache_access"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Returns None for: None, blank, non-matching lines.
        Fields: client_ip, ident, user, time, method, uri, protocol,
        status, bytes, referer, user_agent.
        '-' values stored as None.
        referer/user_agent are None for Common Log Format (no combined fields).
        """
```

---

### 8.6 `loghunter/ingest/normalizer.py` 🔲 NEXT — Phase 1

**Test file:** `tests/testIngest/testNormalizer.py`

```
OCSFNormalizer
├── __init__(registry, mitre_mapper, audit_logger)
├── register_mapping(source_format, class_uid, field_map)
│     Maps raw field names → OCSF dot-notation paths
│     Raises ValueError if source_format already registered for class_uid
├── normalize(raw_dict, source_format) → OCSFEvent
│     Raises UnregisteredFormatError if no mapping registered
│     Unknown raw fields dropped with audit log entry
│     Calls mitre_mapper.map_event() and sets mitre_technique_ids
│     Returns OCSFEvent with all mappable fields populated
└── normalize_batch(raw_dicts, source_format) → tuple[list[OCSFEvent], list[dict]]
      Returns (successes, failures). Never raises.
```

**Field mapping format:**
```python
{
    "source_field_name": "ocsf.dot.notation.path",
    "ts": "time",
    "id.orig_h": "src_endpoint.ip",
    ...
}
```

**Required fields that must always be set by mapping:**
`class_uid`, `activity_id`, `severity_id`, `time`, `metadata.log_source`, `metadata.original_time`

---

### 8.7 `loghunter/ingest/writer.py` 🔲 Phase 1

**Test file:** `tests/testIngest/testWriter.py`

```
ParquetWriter
├── __init__(base_path, audit_logger)
│     base_path: PARQUET_BASE_PATH from config
├── write_batch(events: list[OCSFEvent]) → int
│     Groups events by class_uid
│     Writes via pyarrow directly — NOT through DuckDB
│     Partition path: {base_path}/class_uid={uid}/part-NNNN.parquet
│     Returns count of events written
│     Calls audit_logger.log_ingest()
├── write_replay_batch(events, session_id) → int
│     Path: {base_path}/replay.parquet/session_id={id}/
│     Raises ReplaySessionNotFoundError on path error
└── get_partition_path(class_uid) → Path
      Returns partition directory path for a class
```

---

## 9. Engine Layer

### 9.1 `loghunter/engine/sqlite_layer.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testEngine/testSqliteLayer.py`

```python
class SQLiteLayer:
    def __init__(self, db_path: str) -> None:
        """
        Opens/creates SQLite DB. Enables WAL mode.
        Creates all tables via _ensure_tables().
        Raises TypeError (None), ValueError (empty/whitespace).
        """

    def execute_write(self, sql: str, params: tuple | dict) -> None:
        """
        Permits: INSERT, UPDATE, DELETE, CREATE.
        Rejects SELECT → ValueError (case-insensitive, whitespace-stripped).
        Raises TypeError (None sql/params), RuntimeError (after close).
        """

    def execute_read(self, sql: str, params: tuple | dict) -> list[dict]:
        """
        Permits SELECT only. Returns list of row dicts.
        Raises TypeError (None), ValueError (non-SELECT), RuntimeError (closed).
        Empty result → [].
        """

    def close(self) -> None:
        """Idempotent — multiple calls are safe no-ops."""
```

**Tables created by `_ensure_tables()`:**
`query_audit`, `ingest_audit`, `rule_audit`, `rules`, `baselines`, `metric_snapshots`

---

### 9.2 `loghunter/engine/duckdb_layer.py` 🔲 Phase 1

**Test file:** `tests/testEngine/testDuckdbLayer.py`

```
DuckDBLayer
├── __init__(base_path)
│     Opens DuckDB with read_only=True
│     Raises TypeError (None), ValueError (empty)
├── execute_query(sql, params, include_replay=False, session_id=None) → list[dict]
│     Never scans replay unless include_replay=True AND session_id provided
│     Raises ValueError if SELECT not in sql
│     Raises PartitionNotFoundError if partition does not exist
│     Raises RuntimeError after close()
├── get_available_partitions() → list[int]
│     Returns list of class_uids with existing Parquet partitions
└── close() → None
      Idempotent
```

**Security constraints:**
- `read_only=True` at driver level — enforced by DuckDB itself
- Never scans replay unless both `include_replay=True` AND `session_id` provided
- `QueryBuilder.execute` hardcoded to `include_replay=False`

---

### 9.3 `loghunter/engine/mitre_mapper.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testEngine/testMitreMapper.py`

```python
@dataclass(frozen=True)
class MappingRule:
    technique_id: str
    class_uid: int
    description: str
    predicate: Callable[[OCSFEvent], bool]

class MitreMapper:
    def __init__(self) -> None:
        """Indexes all built-in rules by class_uid."""

    def map_event(self, event: OCSFEvent) -> list[str]:
        """
        Returns list of matching technique IDs.
        Predicate exceptions → rule skipped, never raised (D-006).
        Raises TypeError if event is None.
        """

    def get_coverage(self) -> dict[int, set[str]]:
        """Returns class_uid → set of technique IDs with rules."""

    def get_rules_for_class(self, class_uid: int) -> list[MappingRule]:
        """Returns copy. Empty list for unsupported class."""
```

**Helper functions (pure, never raise):**
```python
_field(event, path) → object        # Safe field access
_eq(event, path, value) → bool      # Equality check
_contains(event, path, substr) → bool  # Case-insensitive substring
_gt(event, path, threshold) → bool  # Numeric greater-than
_not_none(event, path) → bool       # Field presence check
```

**Built-in rules (16 total):**
| Technique | class_uid | Pattern |
|---|---|---|
| T1078 | 6003 | activity_id=1 AND severity_id=1 |
| T1110 | 6003 | activity_id=2 AND severity_id=3 |
| T1110.001 | 6003 | activity_id=2 AND auth.protocol_name contains "ntlm" |
| T1078.002 | 6003 | activity_id=1 AND actor.user.name contains "\\" |
| T1059 | 4001 | actor.process.name contains "cmd.exe" OR "powershell" |
| T1059.001 | 4001 | actor.process.name contains "powershell" |
| T1055 | 4001 | actor.process.name contains "svchost" AND process.name not None |
| T1053 | 4001 | actor.process.name contains "schtasks" OR "at.exe" |
| T1071 | 3001 | dst_endpoint.port == 80 OR 443 |
| T1048 | 3001 | network.bytes_out > 10,000,000 |
| T1090 | 3001 | dst_endpoint.port > 8080 |
| T1046 | 3001 | dst_endpoint.port not None AND network.bytes_out == 0 |
| T1190 | 3002 | http.response.code contains "5" |
| T1059.007 | 3002 | http.request.url.path contains "<script" |
| T1005 | 1001 | file.path contains system32, /etc/passwd, or /etc/shadow |
| T1070.004 | 1001 | activity_id == 4 |

---

### 9.4 `loghunter/engine/query_builder.py` 🔲 Phase 2

```
QueryBuilder
├── __init__(duckdb_layer)
├── build_sql(class_uid, filters, time_range) → str
│     Raises PartitionNotFoundError if no partition for class_uid
│     Returns parameterised SQL — no string interpolation
└── execute(class_uid, filters, time_range) → list[OCSFEvent]
      Hardcoded include_replay=False
      Converts rows back to OCSFEvent via registry
```

---

### 9.5 `loghunter/engine/baseline.py` 🔲 Phase 2

```
BaselineEngine
├── __init__(sqlite_layer, metric_registry, audit_logger)
├── compute_baseline(entity_type, entity_value, metric_name,
│                    class_uid, events) → None
│     min_observations=30 (D-004: fewer → no baseline written)
│     Computes mean, stddev via scipy.stats
│     Writes to baselines table via SQLiteLayer
└── get_baseline(entity_type, entity_value, metric_name, class_uid)
      → Optional[dict]
      Returns baseline dict or None if not computed yet
```

---

### 9.6 `loghunter/engine/anomaly.py` 🔲 Phase 2

```
AnomalyDetector
├── __init__(baseline_engine, metric_registry)
└── detect(entity_type, entity_value, metric_name,
           class_uid, current_value) → Optional[AnomalyResult]
      Returns None if no baseline exists
      Returns AnomalyResult(z_score, is_anomaly, threshold=3.0)
      is_anomaly = abs(z_score) > 3.0
```

---

### 9.7 `loghunter/engine/sigma_engine.py` 🔲 Phase 2

**Note (D-010):** LLM dependency removed from SigmaEngine. `SigmaDraftGenerator` lives in `loghunter/llm/`. SigmaEngine has no LLM imports.

```
SigmaEngine
├── __init__(sqlite_layer, audit_logger)
├── store_rule(rule_id, yaml_content) → None
│     Computes sha256. Preserves all versions (D-005).
│     Writes to rules table. Logs to rule_audit.
├── confirm_rule(rule_id, session_id) → None
│     Sets analyst_confirmed=True, confirmed_at=now.
│     Raises RuleNotFoundError if rule_id unknown.
├── export_rule(rule_id, format) → str
│     Raises RuleNotFoundError, RuleNotConfirmedError.
│     Only confirmed rules exportable.
├── backtest_rule(rule_id, session_id) → BacktestResult
│     Calls DuckDBLayer with include_replay=True, session_id=session_id.
└── get_rule(rule_id) → dict
      Raises RuleNotFoundError if not found.
```

---

### 9.8 `loghunter/engine/replay_engine.py` 🔲 Phase 2

```
ReplayEngine
├── __init__(parquet_writer, sigma_engine, duckdb_layer)
├── create_session(name) → str
│     Returns new session_id (UUID)
├── ingest_to_session(events, session_id) → int
│     Calls parquet_writer.write_replay_batch()
│     Raises ReplaySessionNotFoundError if session invalid
└── test_rule_against_session(rule_id, session_id) → BacktestResult
      Only entry point that passes include_replay=True to DuckDBLayer
```

---

### 9.9 `loghunter/engine/ioc_matcher.py` 🔲 Phase 2

```
IOCMatcher
├── __init__(ioc_dir)
│     Loads IOC flat files from ioc_dir
│     Row cap per file: 100,000 (D-008)
├── load_iocs(filename) → int
│     Returns count loaded
├── match_event(event) → list[str]
│     Returns list of matched IOC values
└── get_ioc_count() → int
```

---

## 10. Audit Layer

### 10.1 `loghunter/audit/logger.py` ✅ COMPLETE — 100% coverage

**Test file:** `tests/testAudit/testLogger.py`

```python
class AuditLogger:
    def __init__(self, sqlite_layer: SQLiteLayer) -> None:
        """Raises TypeError if sqlite_layer is None."""

    def log_query(self, entry: QueryAuditEntry) -> None:
        """
        Never raises on write failure — logs to stderr instead.
        Raises TypeError if entry is None.
        This ensures audit failure never disrupts analyst queries.
        """

    def log_ingest(self, entry: IngestAuditEntry) -> None:
        """Raises TypeError if entry is None."""

    def log_rule_event(self, entry: RuleAuditEntry) -> None:
        """Raises TypeError if entry is None."""

    def get_query_history(
        self, session_id: Optional[str] = None, limit: int = 100
    ) -> list[QueryAuditEntry]:
        """
        Most recent first. Optionally filtered by session_id.
        Raises ValueError if limit < 1.
        """

    def get_ingest_history(self, limit: int = 50) -> list[IngestAuditEntry]:
        """Most recent first. Raises ValueError if limit < 1."""
```

**Append-only guarantee:** No `delete`, `update`, or `truncate` methods exist. The audit log cannot be cleared via any public interface.

---

## 11. LLM Layer

### 11.1 `loghunter/llm/anomaly_explainer.py` 🔲 Phase 2

```
AnomalyExplainer
├── __init__(ollama_client, model)
│     If Ollama unavailable → logs warning, all explain() return placeholder (D-003)
└── explain(anomaly_result, entity_context) → str
      Returns human-readable explanation string
      Never raises if Ollama unavailable — returns placeholder
```

---

### 11.2 `loghunter/llm/sigma_draft_generator.py` 🔲 Phase 2

```
SigmaDraftGenerator
├── __init__(ollama_client, model)
└── generate_draft(event, mitre_techniques) → str
      Returns Sigma YAML draft string
      Never raises if Ollama unavailable — returns empty template
```

**Note (D-010):** This class is intentionally separate from `SigmaEngine`. `SigmaEngine` has zero LLM dependencies — rule storage, confirmation, export, and backtesting all work without Ollama.

---

## 12. UI Layer

### 12.1 `loghunter/ui/app.py` 🔲 Phase 3

Streamlit entry point. Tab layout:

| Tab | File | Description |
|---|---|---|
| Ingest | `ingest_tab.py` | Upload logs, run normalizer, write Parquet |
| Query | `query_tab.py` | DuckDB query builder UI |
| Baseline | `baseline_tab.py` | View/compute baselines, anomaly scores |
| Sigma | `sigma_tab.py` | Draft/confirm/export Sigma rules |
| Replay | `replay_tab.py` | Create sessions, backtest rules |
| Coverage | `coverage_tab.py` | ATT&CK coverage matrix from MitreMapper |

---

## 13. Test Coverage Summary

| File | Tests | Coverage | Status |
|---|---|---|---|
| `loghunter/exceptions.py` | testExceptions.py | 100% | ✅ |
| `loghunter/config.py` | testConfig.py | 100% | ✅ |
| `loghunter/schema/ocsf_field_registry.py` | 100 tests | **100%** | ✅ |
| `loghunter/schema/ocsf_event.py` | ~80 tests | **100%** | ✅ |
| `loghunter/schema/metric_registry.py` | ~70 tests | **100%** | ✅ |
| `loghunter/schema/audit_models.py` | ~30 tests | **100%** | ✅ |
| `loghunter/engine/sqlite_layer.py` | ~40 tests | **100%** | ✅ |
| `loghunter/engine/mitre_mapper.py` | ~60 tests | **100%** | ✅ |
| `loghunter/audit/logger.py` | ~45 tests | **100%** | ✅ |
| `loghunter/ingest/parsers/base.py` | 12 tests | **100%** | ✅ |
| `loghunter/ingest/parsers/zeek.py` | ~15 tests | **100%** | ✅ |
| `loghunter/ingest/parsers/evtx.py` | ~18 tests | **100%** | ✅ |
| `loghunter/ingest/parsers/syslog.py` | ~12 tests | **100%** | ✅ |
| `loghunter/ingest/parsers/apache.py` | ~15 tests | **100%** | ✅ |
| `loghunter/ingest/normalizer.py` | — | 🔲 NEXT | — |
| `loghunter/ingest/writer.py` | — | 🔲 Phase 1 | — |
| `loghunter/engine/duckdb_layer.py` | — | 🔲 Phase 1 | — |

### Test Standards
- Every branch must be covered — `--cov-branch` always enabled
- Input space partitioning: every parameter space boundary tested
- `pytest.raises` always asserts on the specific exception subclass
- Coverage command: `pytest <test_file> --cov=<module.dot.path> --cov-report=term-missing`
- `fail_under=80` in `pyproject.toml` — CI blocks on <80%
- Target: 100% on every completed file

### `tests/conftest.py` Fixtures
```python
@pytest.fixture(scope="session")
def ocsf_registry():
    """Loaded from real config/ocsf_schema.json — corruption surfaces as test failure."""
    return OCSFFieldRegistry("config/ocsf_schema.json")

@pytest.fixture(scope="session")
def metric_registry():
    return MetricRegistry("config/metrics.json")

@pytest.fixture
def sqlite_layer(tmp_path):
    layer = SQLiteLayer(str(tmp_path / "test.db"))
    yield layer
    layer.close()

@pytest.fixture
def audit_logger(tmp_path):
    layer = SQLiteLayer(str(tmp_path / "audit.db"))
    yield AuditLogger(layer)
    layer.close()

@pytest.fixture
def tmp_parquet_path(tmp_path):
    return tmp_path / "logs.parquet"

@pytest.fixture
def make_ocsf_event(ocsf_registry):
    def _factory(class_uid=6003, activity_id=1, severity_id=1, **kwargs):
        return OCSFEvent(
            class_uid=class_uid, activity_id=activity_id,
            severity_id=severity_id,
            time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            metadata_log_source="test",
            metadata_original_time="2026-01-01T00:00:00Z",
            registry=ocsf_registry, **kwargs
        )
    return _factory
```

---

## 14. Architectural Decisions

Documented in `DECISIONS.md`. Summary:

| ID | Decision | Rationale |
|---|---|---|
| D-001 | Empty string treated same as None → ValueError | Consistent null semantics |
| D-002 | Duplicate events ingested without dedup | Dedup is query-time, not ingest-time |
| D-003 | LLM unavailable → placeholder returned, never raises | Analyst workflow unblocked |
| D-004 | Baseline requires min 30 observations | Statistically meaningful stddev |
| D-005 | All rule versions preserved, never deleted | Full audit trail |
| D-006 | Absent fields in MITRE predicates → False, never raise | Silent non-match |
| D-007 | Zero ATT&CK coverage is valid initial state | No synthetic rules |
| D-008 | IOC file row cap 100,000 | Memory bound |
| D-009 | DuckDB read-only enforced at driver level + string scan | Defense in depth |
| D-010 | SigmaEngine has no LLM dependency | Clean separation, offline capable |
| D-011 | PartitionNotFoundError raised specifically (not generic StorageError) | UI surfaces meaningful message |
| D-012 | Duplicate field_path in ocsf_schema.json → applicable_classes merged | Deliberate for dst_endpoint.hostname |

---

## 15. Phase Build Order

### Phase 1 — Data Pipeline (14/17 complete)
| # | File | Status |
|---|---|---|
| 1 | `OCSFFieldRegistry` | ✅ 100% |
| 2 | `OCSFEvent` | ✅ 100% |
| 3 | `MetricRegistry` | ✅ 100% |
| 4 | `SQLiteLayer` | ✅ 100% |
| 5 | `AuditLogger` | ✅ 100% |
| 6 | `LogParser` + subclasses (4) | ✅ 100% |
| 7 | `MitreMapper` | ✅ 100% |
| 8 | `OCSFNormalizer` | 🔲 NEXT |
| 9 | `ParquetWriter` | 🔲 |
| 10 | `DuckDBLayer` | 🔲 |

**Phase 1 goal:** End-to-end data pipeline working with real logs. No LLM.

### Phase 2 — Detection Logic
`QueryBuilder` → `BaselineEngine` → `AnomalyDetector` → `SigmaEngine` → `ReplayEngine` → `IOCMatcher` → `AnomalyExplainer` → `SigmaDraftGenerator`

### Phase 3 — UI
`app.py` → all 6 tabs → 3 components

---

## 16. CI/CD

**File:** `.github/workflows/ci.yml`

- Triggers: push and PR to `develop` and `main`
- Matrix: Python 3.11 and 3.12
- Steps: checkout → setup Python (pip cache) → install deps → pytest with branch coverage
- Fails if coverage < 80%
- Uploads HTML coverage report as artifact (14-day retention)
- **CI workflow changes require dedicated PR with written justification**

```yaml
- name: Run tests
  run: |
    pytest --cov=loghunter --cov-branch --cov-report=term-missing \
           --cov-fail-under=80
```

---

*End of LogHunt Specification v2.0*