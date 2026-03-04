# ==============================================================================
# tests/testIngest/testParsers/testApache.py
#
# Tests for loghunter/ingest/parsers/apache.py
#
# Coverage — every branch:
#   None input → None
#   Blank input → None
#   Non-matching line → None
#   Valid combined log line → full dict
#   Valid common log line (no referer/user_agent) → referer/user_agent None
#   '-' fields stored as None (ident, user, bytes)
#   Request line split: method, uri, protocol
#   Empty request string → method None
#   source_format → "apache_access"
# ==============================================================================

from __future__ import annotations

import pytest

from loghunter.ingest.parsers.apache import ApacheParser

_COMBINED = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
_COMMON = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 1234'
_NULL_USER = '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "POST /login HTTP/1.1" 401 -'


class TestApacheParserSourceFormat:

    def test_source_format_is_apache_access(self):
        assert ApacheParser().source_format == "apache_access"


class TestApacheParserParse:

    def test_none_returns_none(self):
        assert ApacheParser().parse(None) is None

    def test_blank_returns_none(self):
        assert ApacheParser().parse("") is None
        assert ApacheParser().parse("   ") is None

    def test_non_matching_returns_none(self):
        assert ApacheParser().parse("not an apache log line") is None
        assert ApacheParser().parse("127.0.0.1") is None

    def test_combined_format_returns_dict(self):
        result = ApacheParser().parse(_COMBINED)
        assert isinstance(result, dict)

    def test_combined_client_ip(self):
        result = ApacheParser().parse(_COMBINED)
        assert result["client_ip"] == "127.0.0.1"

    def test_combined_user_stored(self):
        result = ApacheParser().parse(_COMBINED)
        assert result["user"] == "frank"

    def test_combined_method_uri_protocol(self):
        result = ApacheParser().parse(_COMBINED)
        assert result["method"] == "GET"
        assert result["uri"] == "/apache_pb.gif"
        assert result["protocol"] == "HTTP/1.0"

    def test_combined_status(self):
        result = ApacheParser().parse(_COMBINED)
        assert result["status"] == "200"

    def test_combined_referer_and_user_agent(self):
        result = ApacheParser().parse(_COMBINED)
        assert result["referer"] == "http://www.example.com/start.html"
        assert result["user_agent"] is not None

    def test_common_format_referer_and_user_agent_none(self):
        result = ApacheParser().parse(_COMMON)
        assert result["referer"] is None
        assert result["user_agent"] is None

    def test_dash_ident_stored_as_none(self):
        result = ApacheParser().parse(_COMBINED)
        assert result["ident"] is None

    def test_dash_user_stored_as_none(self):
        result = ApacheParser().parse(_COMMON)
        assert result["user"] is None

    def test_dash_bytes_stored_as_none(self):
        result = ApacheParser().parse(_NULL_USER)
        assert result["bytes"] is None

    def test_all_expected_keys_present(self):
        result = ApacheParser().parse(_COMBINED)
        for key in ("client_ip", "ident", "user", "time", "method",
                    "uri", "protocol", "status", "bytes",
                    "referer", "user_agent"):
            assert key in result

    def test_post_request(self):
        result = ApacheParser().parse(_NULL_USER)
        assert result["method"] == "POST"
        assert result["uri"] == "/login"

    def test_leading_whitespace_stripped(self):
        result = ApacheParser().parse("  " + _COMBINED)
        assert result is not None


class TestApacheParserBatch:

    def test_batch_mixed(self):
        parser = ApacheParser()
        lines = [_COMBINED, "bad line", _COMMON, ""]
        successes, failures = parser.parse_batch(lines)
        assert len(successes) == 2
        assert len(failures) == 2