# tests/testUI/testHunt.py — 100% branch coverage for hunt.py pure functions
import sys
from unittest.mock import MagicMock
sys.modules["streamlit"] = MagicMock()

import pytest
from loghunter.ui.tabs.hunt import decode_uploaded_file, run_ingest, build_summary_message, FORMAT_OPTIONS, CLASS_UID_NAMES


class TestDecodeUploadedFile:
    def test_none_raises_type_error(self):
        with pytest.raises(TypeError, match="raw_bytes must not be None"):
            decode_uploaded_file(None)

    def test_empty_raises_value_error(self):
        with pytest.raises(ValueError, match="raw_bytes must not be empty"):
            decode_uploaded_file(b"")

    def test_utf8_decoded(self):
        lines = decode_uploaded_file(b"line1\nline2\n")
        assert lines == ["line1", "line2"]

    def test_latin1_fallback(self):
        # byte 0x80 is invalid utf-8, valid latin-1
        data = "caf\xe9\nline2".encode("latin-1")
        lines = decode_uploaded_file(data)
        assert len(lines) == 2

    def test_empty_lines_excluded(self):
        lines = decode_uploaded_file(b"line1\n\n   \nline2")
        assert lines == ["line1", "line2"]

    def test_single_line_no_newline(self):
        lines = decode_uploaded_file(b"single")
        assert lines == ["single"]


class TestRunIngest:
    def _setup(self, parse_result=None, norm_result=None, write_result=5):
        parser_class = MagicMock()
        parser_instance = MagicMock()
        parser_instance.parse_lines.return_value = parse_result or [{"k": "v"}]
        parser_class.return_value = parser_instance

        normalizer = MagicMock()
        events = [MagicMock()] * (len(parse_result) if parse_result else 1)
        normalizer.normalize_batch.return_value = (
            norm_result if norm_result is not None else (events, [])
        )

        writer = MagicMock()
        writer.write_batch.return_value = write_result

        return parser_class, normalizer, writer

    def test_happy_path_returns_correct_counts(self):
        parser_class, normalizer, writer = self._setup(
            parse_result=[{"k":"v"},{"k":"v"}],
            norm_result=([MagicMock(), MagicMock()], []),
            write_result=2
        )
        result = run_ingest(["l1","l2"], "zeek", 3001, parser_class, normalizer, writer)
        assert result["parsed_count"] == 2
        assert result["written_count"] == 2
        assert result["error"] is None

    def test_parse_failures_counted(self):
        parser_class, normalizer, writer = self._setup(
            parse_result=[{"k":"v"}],  # 1 parsed from 3 lines
        )
        result = run_ingest(["l1","l2","l3"], "zeek", 3001, parser_class, normalizer, writer)
        assert result["failed_parse"] == 2

    def test_normalise_failures_counted(self):
        parser_class, normalizer, writer = self._setup(
            parse_result=[{"k":"v"},{"k":"v"}],
            norm_result=([MagicMock()], [{"k":"v"}]),
        )
        result = run_ingest(["l1","l2"], "zeek", 3001, parser_class, normalizer, writer)
        assert result["failed_normalise"] == 1

    def test_exception_returns_error_dict(self):
        parser_class = MagicMock()
        parser_class.return_value.parse_lines.side_effect = RuntimeError("boom")
        result = run_ingest(["l1"], "zeek", 3001, parser_class, MagicMock(), MagicMock())
        assert result["error"] == "boom"
        assert result["written_count"] == 0

    def test_default_file_name(self):
        parser_class, normalizer, writer = self._setup()
        result = run_ingest(["l1"], "zeek", 3001, parser_class, normalizer, writer)
        writer.write_batch.assert_called_once()
        call_args = writer.write_batch.call_args
        assert "unknown" in str(call_args)


class TestBuildSummaryMessage:
    def test_error_returns_x_prefix(self):
        msg = build_summary_message({"error": "boom", "written_count": 0, "failed_parse": 0, "failed_normalise": 0})
        assert msg.startswith("❌")
        assert "boom" in msg

    def test_success_returns_checkmark(self):
        msg = build_summary_message({"error": None, "written_count": 10, "failed_parse": 1, "failed_normalise": 2})
        assert msg.startswith("✅")
        assert "10" in msg

    def test_failure_counts_included(self):
        msg = build_summary_message({"error": None, "written_count": 5, "failed_parse": 3, "failed_normalise": 1})
        assert "3" in msg and "1" in msg


class TestFormatOptions:
    def test_covers_all_five_classes(self):
        class_uids = {v[1] for v in FORMAT_OPTIONS.values()}
        assert class_uids == {1001, 3001, 3002, 4001, 6003}

    def test_each_option_has_three_elements(self):
        for label, (fmt, uid, cls) in FORMAT_OPTIONS.items():
            assert isinstance(fmt, str)
            assert isinstance(uid, int)
            assert isinstance(cls, type)

    def test_class_uid_names_all_five(self):
        assert set(CLASS_UID_NAMES.keys()) == {1001, 3001, 3002, 4001, 6003}