#!/usr/bin/env bash
# ==============================================================================
# LogHunt — Project Initialisation Script
# Run once from the LogHunt/ root directory:  bash init_project.sh
# ==============================================================================

set -e

echo "Creating directory structure..."

# --- Source directories -------------------------------------------------------
mkdir -p loghunter/schema
mkdir -p loghunter/ingest/parsers
mkdir -p loghunter/engine
mkdir -p loghunter/llm
mkdir -p loghunter/audit
mkdir -p loghunter/ui/tabs
mkdir -p loghunter/ui/components

# --- Test directories (mirror loghunter/ with test prefix) --------------------
mkdir -p tests/testSchema
mkdir -p tests/testIngest/testParsers
mkdir -p tests/testEngine
mkdir -p tests/testLlm
mkdir -p tests/testAudit
mkdir -p tests/integration
mkdir -p tests/security

# --- Config, data, docs, rules, iocs ------------------------------------------
mkdir -p config
mkdir -p data/sample
mkdir -p data/logs.parquet
mkdir -p data/replay.parquet
mkdir -p docs
mkdir -p rules/confirmed
mkdir -p rules/drafts
mkdir -p iocs
mkdir -p scripts
mkdir -p .github/workflows

echo "Creating __init__.py files..."

# --- Package init files -------------------------------------------------------
touch loghunter/__init__.py
touch loghunter/schema/__init__.py
touch loghunter/ingest/__init__.py
touch loghunter/ingest/parsers/__init__.py
touch loghunter/engine/__init__.py
touch loghunter/llm/__init__.py
touch loghunter/audit/__init__.py
touch loghunter/ui/__init__.py
touch loghunter/ui/tabs/__init__.py
touch loghunter/ui/components/__init__.py

# --- Test package init files --------------------------------------------------
touch tests/__init__.py
touch tests/testSchema/__init__.py
touch tests/testIngest/__init__.py
touch tests/testIngest/testParsers/__init__.py
touch tests/testEngine/__init__.py
touch tests/testLlm/__init__.py
touch tests/testAudit/__init__.py
touch tests/integration/__init__.py
touch tests/security/__init__.py

echo "Creating source stubs..."

# --- loghunter/ root ----------------------------------------------------------
touch loghunter/config.py
touch loghunter/exceptions.py

# --- schema/ ------------------------------------------------------------------
touch loghunter/schema/ocsf_field_registry.py
touch loghunter/schema/ocsf_event.py
touch loghunter/schema/metric_registry.py
touch loghunter/schema/query_intent.py
touch loghunter/schema/audit_models.py

# --- ingest/ ------------------------------------------------------------------
touch loghunter/ingest/normalizer.py
touch loghunter/ingest/writer.py

# --- ingest/parsers/ ----------------------------------------------------------
touch loghunter/ingest/parsers/base.py
touch loghunter/ingest/parsers/zeek.py
touch loghunter/ingest/parsers/evtx.py
touch loghunter/ingest/parsers/syslog.py
touch loghunter/ingest/parsers/apache.py

# --- engine/ ------------------------------------------------------------------
touch loghunter/engine/duckdb_layer.py
touch loghunter/engine/sqlite_layer.py
touch loghunter/engine/query_builder.py
touch loghunter/engine/baseline.py
touch loghunter/engine/anomaly.py
touch loghunter/engine/sigma_engine.py
touch loghunter/engine/mitre_mapper.py
touch loghunter/engine/coverage.py
touch loghunter/engine/ioc_matcher.py
touch loghunter/engine/replay.py

# --- llm/ ---------------------------------------------------------------------
touch loghunter/llm/intent_extractor.py
touch loghunter/llm/anomaly_explainer.py
touch loghunter/llm/sigma_draft_generator.py
touch loghunter/llm/prompts.py

# --- audit/ -------------------------------------------------------------------
touch loghunter/audit/logger.py
touch loghunter/audit/metrics.py

# --- ui/ stubs ----------------------------------------------------------------
touch loghunter/ui/tabs/investigate.py
touch loghunter/ui/tabs/hunt.py
touch loghunter/ui/tabs/rules.py
touch loghunter/ui/tabs/coverage.py
touch loghunter/ui/tabs/metrics.py
touch loghunter/ui/tabs/settings.py
touch loghunter/ui/components/results_table.py
touch loghunter/ui/components/timeline_chart.py
touch loghunter/ui/components/attack_heatmap.py

# --- scripts/ -----------------------------------------------------------------
touch scripts/init_db.py
touch scripts/ingest.py
touch scripts/benchmark.py

# --- app entry point ----------------------------------------------------------
touch app.py

echo "Creating test stubs..."

# --- tests/ root --------------------------------------------------------------
cat > tests/testConfig.py << 'PYEOF'
# tests/testConfig.py
# Tests for loghunter/config.py


class TestConfig:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testExceptions.py << 'PYEOF'
# tests/testExceptions.py
# Tests for loghunter/exceptions.py


class TestExceptions:
    def test_placeholder(self):
        pass
PYEOF

# --- testSchema/ --------------------------------------------------------------
cat > tests/testSchema/testOcsfFieldRegistry.py << 'PYEOF'
# tests/testSchema/testOcsfFieldRegistry.py
# Tests for loghunter/schema/ocsf_field_registry.py


class TestOcsfFieldRegistry:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testSchema/testOcsfEvent.py << 'PYEOF'
# tests/testSchema/testOcsfEvent.py
# Tests for loghunter/schema/ocsf_event.py


class TestOcsfEvent:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testSchema/testMetricRegistry.py << 'PYEOF'
# tests/testSchema/testMetricRegistry.py
# Tests for loghunter/schema/metric_registry.py


class TestMetricRegistry:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testSchema/testQueryIntent.py << 'PYEOF'
# tests/testSchema/testQueryIntent.py
# Tests for loghunter/schema/query_intent.py


class TestQueryIntent:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testSchema/testAuditModels.py << 'PYEOF'
# tests/testSchema/testAuditModels.py
# Tests for loghunter/schema/audit_models.py


class TestAuditModels:
    def test_placeholder(self):
        pass
PYEOF

# --- testIngest/ --------------------------------------------------------------
cat > tests/testIngest/testNormalizer.py << 'PYEOF'
# tests/testIngest/testNormalizer.py
# Tests for loghunter/ingest/normalizer.py


class TestOcsfNormalizer:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testIngest/testWriter.py << 'PYEOF'
# tests/testIngest/testWriter.py
# Tests for loghunter/ingest/writer.py


class TestParquetWriter:
    def test_placeholder(self):
        pass
PYEOF

# --- testIngest/testParsers/ --------------------------------------------------
cat > tests/testIngest/testParsers/testBase.py << 'PYEOF'
# tests/testIngest/testParsers/testBase.py
# Tests for loghunter/ingest/parsers/base.py


class TestLogParser:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testIngest/testParsers/testZeek.py << 'PYEOF'
# tests/testIngest/testParsers/testZeek.py
# Tests for loghunter/ingest/parsers/zeek.py


class TestZeekParser:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testIngest/testParsers/testEvtx.py << 'PYEOF'
# tests/testIngest/testParsers/testEvtx.py
# Tests for loghunter/ingest/parsers/evtx.py


class TestEvtxParser:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testIngest/testParsers/testSyslog.py << 'PYEOF'
# tests/testIngest/testParsers/testSyslog.py
# Tests for loghunter/ingest/parsers/syslog.py


class TestSyslogParser:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testIngest/testParsers/testApache.py << 'PYEOF'
# tests/testIngest/testParsers/testApache.py
# Tests for loghunter/ingest/parsers/apache.py


class TestApacheParser:
    def test_placeholder(self):
        pass
PYEOF

# --- testEngine/ --------------------------------------------------------------
cat > tests/testEngine/testDuckdbLayer.py << 'PYEOF'
# tests/testEngine/testDuckdbLayer.py
# Tests for loghunter/engine/duckdb_layer.py


class TestDuckdbLayer:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testSqliteLayer.py << 'PYEOF'
# tests/testEngine/testSqliteLayer.py
# Tests for loghunter/engine/sqlite_layer.py


class TestSqliteLayer:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testQueryBuilder.py << 'PYEOF'
# tests/testEngine/testQueryBuilder.py
# Tests for loghunter/engine/query_builder.py


class TestQueryBuilder:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testBaseline.py << 'PYEOF'
# tests/testEngine/testBaseline.py
# Tests for loghunter/engine/baseline.py


class TestBaselineEngine:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testAnomaly.py << 'PYEOF'
# tests/testEngine/testAnomaly.py
# Tests for loghunter/engine/anomaly.py


class TestAnomalyDetector:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testSigmaEngine.py << 'PYEOF'
# tests/testEngine/testSigmaEngine.py
# Tests for loghunter/engine/sigma_engine.py


class TestSigmaEngine:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testMitreMapper.py << 'PYEOF'
# tests/testEngine/testMitreMapper.py
# Tests for loghunter/engine/mitre_mapper.py


class TestMitreMapper:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testCoverage.py << 'PYEOF'
# tests/testEngine/testCoverage.py
# Tests for loghunter/engine/coverage.py


class TestCoverageAnalyzer:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testIocMatcher.py << 'PYEOF'
# tests/testEngine/testIocMatcher.py
# Tests for loghunter/engine/ioc_matcher.py


class TestIocMatcher:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testEngine/testReplay.py << 'PYEOF'
# tests/testEngine/testReplay.py
# Tests for loghunter/engine/replay.py


class TestReplayEngine:
    def test_placeholder(self):
        pass
PYEOF

# --- testLlm/ -----------------------------------------------------------------
cat > tests/testLlm/testIntentExtractor.py << 'PYEOF'
# tests/testLlm/testIntentExtractor.py
# Tests for loghunter/llm/intent_extractor.py


class TestIntentExtractor:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testLlm/testAnomalyExplainer.py << 'PYEOF'
# tests/testLlm/testAnomalyExplainer.py
# Tests for loghunter/llm/anomaly_explainer.py


class TestAnomalyExplainer:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testLlm/testSigmaDraftGenerator.py << 'PYEOF'
# tests/testLlm/testSigmaDraftGenerator.py
# Tests for loghunter/llm/sigma_draft_generator.py


class TestSigmaDraftGenerator:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testLlm/testPrompts.py << 'PYEOF'
# tests/testLlm/testPrompts.py
# Tests for loghunter/llm/prompts.py


class TestPrompts:
    def test_placeholder(self):
        pass
PYEOF

# --- testAudit/ ---------------------------------------------------------------
cat > tests/testAudit/testLogger.py << 'PYEOF'
# tests/testAudit/testLogger.py
# Tests for loghunter/audit/logger.py


class TestAuditLogger:
    def test_placeholder(self):
        pass
PYEOF

cat > tests/testAudit/testMetrics.py << 'PYEOF'
# tests/testAudit/testMetrics.py
# Tests for loghunter/audit/metrics.py


class TestMetricsCollector:
    def test_placeholder(self):
        pass
PYEOF

echo "Creating config files..."

# --- pyproject.toml -----------------------------------------------------------
cat > pyproject.toml << 'TOMLEOF'
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]

[tool.coverage.run]
branch = true
source = ["loghunter"]
omit = ["tests/*", "scripts/*"]

[tool.coverage.report]
show_missing = true
fail_under = 80

[tool.coverage.html]
directory = "htmlcov"
TOMLEOF

# --- requirements.txt ---------------------------------------------------------
cat > requirements.txt << 'EOF'
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
EOF

# --- requirements-dev.txt -----------------------------------------------------
cat > requirements-dev.txt << 'EOF'
pytest==8.2.2
pytest-cov==5.0.0
pytest-mock==3.14.0
hypothesis==6.103.4
coverage==7.5.3
EOF

# --- .env.example -------------------------------------------------------------
cat > .env.example << 'EOF'
# Copy this file to .env and fill in values. Never commit .env.

# Ollama / LLM
OLLAMA_HOST=http://localhost:11434
LLM_MODEL=llama3

# Storage paths (relative to project root)
# DuckDB reads Parquet from here (read-only analytical layer)
PARQUET_BASE_PATH=./data/logs.parquet
# SQLite stores all application metadata: audit log, baselines, rule store
METADATA_DB_PATH=./data/metadata.db

# Application
LOG_LEVEL=INFO
EOF

# --- .gitignore ---------------------------------------------------------------
cat > .gitignore << 'EOF'
# Virtual environment
venv/
.venv/
env/

# Environment / secrets
.env

# Python cache
__pycache__/
*.py[cod]
*.pyo

# Data — never commit
data/
*.db

# Coverage
htmlcov/
.coverage
.coverage.*

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Build
*.egg-info/
dist/
build/
*.egg

# Jupyter
.ipynb_checkpoints/

# Logs
*.log

# Local config overrides
config/local/

# Pytest / coverage cache
.pytest_cache/
.mypy_cache/
EOF

# --- GitHub Actions CI --------------------------------------------------------
cat > .github/workflows/ci.yml << 'EOF'
name: CI

on:
  push:
    branches: ["**"]
  pull_request:
    branches: [develop, main]

jobs:
  test:
    name: Test Suite (Python ${{ matrix.python-version }})
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: pip
      - run: pip install -r requirements.txt
      - run: pip install -r requirements-dev.txt
      - run: pytest --cov=loghunter --cov-report=term-missing --cov-report=html --cov-fail-under=80 -v
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: coverage-report-py${{ matrix.python-version }}
          path: htmlcov/
          retention-days: 14
EOF

# --- conftest.py --------------------------------------------------------------
cat > tests/conftest.py << 'PYEOF'
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
PYEOF

echo ""
echo "Done. Full structure:"
find . -not -path '*/\.*' -not -path './data/*' -not -path './__pycache__/*' -type f | sort
echo ""
echo "Next: pip install -r requirements.txt && pip install -r requirements-dev.txt"
echo "Then: pytest  (all placeholders should pass)"
