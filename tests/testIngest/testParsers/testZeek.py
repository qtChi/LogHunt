# ==============================================================================
# tests/testIngest/testParsers/testZeek.py
#
# Tests for loghunter/ingest/parsers/zeek.py
#
# Coverage — every branch:
#   None input → None
#   Blank line → None
#   # comment line (non-fields) → None
#   #fields header → updates self._fields, returns None
#   Wrong field count → None
#   Valid TSV line → dict with correct values
#   '-' values → stored as None
#   source_format → "zeek_conn"
#   #fields header with single field part → not updated (len <= 1)
# ==============================================================================

from __future__ import annotations

import pytest

from loghunter.ingest.parsers.zeek import ZeekParser, _DEFAULT_FIELDS

# A valid minimal Zeek conn.log line matching _DEFAULT_FIELDS (21 fields)
_VALID_LINE = "\t".join([
    "1609459200.0",  # ts
    "CAbCdE",        # uid
    "192.168.1.1",   # id.orig_h
    "54321",         # id.orig_p
    "8.8.8.8",       # id.resp_h
    "443",           # id.resp_p
    "tcp",           # proto
    "ssl",           # service
    "1.234",         # duration
    "512",           # orig_bytes
    "1024",          # resp_bytes
    "SF",            # conn_state
    "-",             # local_orig (null)
    "-",             # local_resp (null)
    "0",             # missed_bytes
    "ShADadfFr",     # history
    "5",             # orig_pkts
    "768",           # orig_ip_bytes
    "4",             # resp_pkts
    "1280",          # resp_ip_bytes
    "-",             # tunnel_parents (null)
])

_FIELDS_HEADER = "#fields\t" + "\t".join(["col_a", "col_b", "col_c"])


class TestZeekParserSourceFormat:

    def test_source_format_is_zeek_conn(self):
        assert ZeekParser().source_format == "zeek_conn"


class TestZeekParserParse:

    def test_none_returns_none(self):
        assert ZeekParser().parse(None) is None

    def test_blank_line_returns_none(self):
        assert ZeekParser().parse("") is None
        assert ZeekParser().parse("   ") is None

    def test_comment_line_returns_none(self):
        assert ZeekParser().parse("#separator \\x09") is None
        assert ZeekParser().parse("#close 2026-01-01") is None

    def test_fields_header_returns_none_and_updates_fields(self):
        parser = ZeekParser()
        result = parser.parse(_FIELDS_HEADER)
        assert result is None
        assert parser._fields == ["col_a", "col_b", "col_c"]

    def test_fields_header_single_part_not_updated(self):
        # "#fields" with no tab-separated names — len(parts) == 1
        parser = ZeekParser()
        original = list(parser._fields)
        parser.parse("#fields")
        assert parser._fields == original

    def test_wrong_field_count_returns_none(self):
        parser = ZeekParser()
        short_line = "ts\tuid\t192.168.1.1"  # only 3 fields
        assert parser.parse(short_line) is None

    def test_valid_line_returns_dict(self):
        parser = ZeekParser()
        result = parser.parse(_VALID_LINE)
        assert isinstance(result, dict)

    def test_valid_line_correct_field_count(self):
        parser = ZeekParser()
        result = parser.parse(_VALID_LINE)
        assert len(result) == len(_DEFAULT_FIELDS)

    def test_valid_line_field_values_correct(self):
        parser = ZeekParser()
        result = parser.parse(_VALID_LINE)
        assert result["id.orig_h"] == "192.168.1.1"
        assert result["id.resp_p"] == "443"
        assert result["proto"] == "tcp"

    def test_dash_values_stored_as_none(self):
        parser = ZeekParser()
        result = parser.parse(_VALID_LINE)
        assert result["local_orig"] is None
        assert result["local_resp"] is None
        assert result["tunnel_parents"] is None

    def test_non_dash_values_not_none(self):
        parser = ZeekParser()
        result = parser.parse(_VALID_LINE)
        assert result["ts"] == "1609459200.0"
        assert result["uid"] == "CAbCdE"

    def test_custom_fields_after_header_update(self):
        parser = ZeekParser()
        parser.parse("#fields\tcol_a\tcol_b\tcol_c")
        result = parser.parse("val_a\tval_b\tval_c")
        assert result == {"col_a": "val_a", "col_b": "val_b", "col_c": "val_c"}

    def test_all_null_values_line(self):
        parser = ZeekParser()
        parser.parse("#fields\ta\tb\tc")
        result = parser.parse("-\t-\t-")
        assert result == {"a": None, "b": None, "c": None}


class TestZeekParserBatch:

    def test_batch_mixed_lines(self):
        parser = ZeekParser()
        lines = [
            "#separator \\x09",
            "#fields\t" + "\t".join(_DEFAULT_FIELDS),
            _VALID_LINE,
            "bad\tshort\tline",
        ]
        successes, failures = parser.parse_batch(lines)
        assert len(successes) == 1
        assert len(failures) == 3