# ==============================================================================
# tests/testIngest/testParsers/testBase.py
#
# Tests for loghunter/ingest/parsers/base.py
#
# Coverage strategy:
#
# LogParser (abstract):
#   Cannot be instantiated directly → TypeError
#   Subclass without source_format → TypeError
#   Subclass without parse → TypeError
#   Concrete subclass constructs
#
# parse_batch:
#   None raw_lines → TypeError
#   Empty list → ([], [])
#   All parse successfully → all in successes
#   All fail → all in failures
#   Mixed → split correctly
#   parse() raising exception → line counted as failure, no raise
#   Blank lines → failures (parse returns None)
# ==============================================================================

from __future__ import annotations

from typing import Optional

import pytest

from loghunter.ingest.parsers.base import LogParser


# ---------------------------------------------------------------------------
# Concrete implementations for testing
# ---------------------------------------------------------------------------

class _AlwaysSucceedParser(LogParser):
    @property
    def source_format(self) -> str:
        return "test_succeed"

    def parse(self, raw_line: str) -> Optional[dict]:
        if not raw_line or not raw_line.strip():
            return None
        return {"line": raw_line.strip()}


class _AlwaysFailParser(LogParser):
    @property
    def source_format(self) -> str:
        return "test_fail"

    def parse(self, raw_line: str) -> Optional[dict]:
        return None


class _RaisingParser(LogParser):
    """parse() raises on every call — parse_batch must not propagate."""
    @property
    def source_format(self) -> str:
        return "test_raising"

    def parse(self, raw_line: str) -> Optional[dict]:
        raise RuntimeError("deliberate error")


class _MixedParser(LogParser):
    """Succeeds on lines starting with 'ok:', fails otherwise."""
    @property
    def source_format(self) -> str:
        return "test_mixed"

    def parse(self, raw_line: str) -> Optional[dict]:
        if raw_line and raw_line.startswith("ok:"):
            return {"value": raw_line[3:]}
        return None


# ==============================================================================
# TestLogParserAbstract
# ==============================================================================

class TestLogParserAbstract:

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            LogParser()

    def test_subclass_missing_source_format_raises(self):
        class _NoFormat(LogParser):
            def parse(self, raw_line):
                return None
        with pytest.raises(TypeError):
            _NoFormat()

    def test_subclass_missing_parse_raises(self):
        class _NoParse(LogParser):
            @property
            def source_format(self):
                return "x"
        with pytest.raises(TypeError):
            _NoParse()

    def test_concrete_subclass_constructs(self):
        parser = _AlwaysSucceedParser()
        assert parser is not None

    def test_source_format_is_string(self):
        parser = _AlwaysSucceedParser()
        assert isinstance(parser.source_format, str)


# ==============================================================================
# TestParseBatch
# ==============================================================================

class TestParseBatch:

    def test_none_raw_lines_raises_type_error(self):
        parser = _AlwaysSucceedParser()
        with pytest.raises(TypeError):
            parser.parse_batch(None)

    def test_empty_list_returns_empty_successes_and_failures(self):
        parser = _AlwaysSucceedParser()
        successes, failures = parser.parse_batch([])
        assert successes == []
        assert failures == []

    def test_all_succeed_returns_all_in_successes(self):
        parser = _AlwaysSucceedParser()
        lines = ["line1", "line2", "line3"]
        successes, failures = parser.parse_batch(lines)
        assert len(successes) == 3
        assert failures == []

    def test_all_fail_returns_all_in_failures(self):
        parser = _AlwaysFailParser()
        lines = ["a", "b", "c"]
        successes, failures = parser.parse_batch(lines)
        assert successes == []
        assert len(failures) == 3

    def test_mixed_split_correctly(self):
        parser = _MixedParser()
        lines = ["ok:value1", "bad_line", "ok:value2", "also_bad"]
        successes, failures = parser.parse_batch(lines)
        assert len(successes) == 2
        assert len(failures) == 2

    def test_raising_parse_counted_as_failure_no_raise(self):
        parser = _RaisingParser()
        lines = ["line1", "line2"]
        successes, failures = parser.parse_batch(lines)
        assert successes == []
        assert len(failures) == 2

    def test_blank_lines_counted_as_failures(self):
        parser = _AlwaysSucceedParser()
        lines = ["good_line", "", "   ", "another_good"]
        successes, failures = parser.parse_batch(lines)
        assert len(successes) == 2
        assert len(failures) == 2

    def test_returns_tuple(self):
        parser = _AlwaysSucceedParser()
        result = parser.parse_batch(["line"])
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_successes_are_dicts(self):
        parser = _AlwaysSucceedParser()
        successes, _ = parser.parse_batch(["line1"])
        assert all(isinstance(r, dict) for r in successes)

    def test_failures_are_strings(self):
        parser = _AlwaysFailParser()
        _, failures = parser.parse_batch(["bad1", "bad2"])
        assert all(isinstance(f, str) for f in failures)

    def test_original_line_preserved_in_failures(self):
        parser = _AlwaysFailParser()
        line = "some raw line content"
        _, failures = parser.parse_batch([line])
        assert failures[0] == line

    def test_single_element_list(self):
        parser = _AlwaysSucceedParser()
        successes, failures = parser.parse_batch(["single"])
        assert len(successes) == 1
        assert len(failures) == 0