# ==============================================================================
# loghunter/config.py
#
# Central configuration loader. Reads from environment variables populated
# by .env via python-dotenv. No component reads os.environ directly —
# everything imports from here.
# ==============================================================================

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


def _optional(key: str, default: str) -> str:
    return os.environ.get(key, default).strip() or default


# --- LLM ----------------------------------------------------------------------
OLLAMA_HOST: str = _optional("OLLAMA_HOST", "http://localhost:11434")
LLM_MODEL: str = _optional("LLM_MODEL", "llama3")

# --- Storage paths ------------------------------------------------------------
# Per spec section 4.1: DuckDB reads Parquet from here (read-only).
# Per spec section 4.2: SQLite at METADATA_DB_PATH stores all mutable state.
PARQUET_BASE_PATH: str = _optional("PARQUET_BASE_PATH", "./data/logs.parquet")
METADATA_DB_PATH: str = _optional("METADATA_DB_PATH", "./data/metadata.db")

# --- Application --------------------------------------------------------------
_LOG_LEVEL_RAW: str = _optional("LOG_LEVEL", "INFO").upper()
LOG_LEVEL: int = getattr(logging, _LOG_LEVEL_RAW, logging.INFO)