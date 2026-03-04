# ==============================================================================
# tests/testIngest/testParsers/testSyslog.py
#
# Tests for loghunter/ingest/parsers/syslog.py
#
# Coverage — every branch:
#   None input → None
#   Blank input → None
#   Non-matching line → None
#   Valid line with PID → all fields set
#   Valid line without PID → pid is None
#   Valid line without priority → priority is None
#   source_format → "syslog"
# ==============================================================================

from __future__ import annotations

import pytest

from loghunter.ingest.parsers.syslog import SyslogParser

_WITH_PRIORITY_PID = "<34>Jan  5 06:00:00 mymachine su[1234]: 'su root' failed"
_WITH_PRIORITY_NO_PID = "<34>Jan  5 06:00:00 mymachine su: 'su root' failed"
_NO_PRIORITY_WITH_PID = "Jan  5 06:00:00 mymachine su[1234]: message here"
_NO_PRIORITY_NO_PID = "Jan  5 06:00:00 mymachine sshd: Connection closed"


class TestSyslogParserSourceFormat:

    def test_source_format_is_syslog(self):
        assert SyslogParser().source_format == "syslog"


class TestSyslogParserParse:

    def test_none_returns_none(self):
        assert SyslogParser().parse(None) is None

    def test_blank_returns_none(self):
        assert SyslogParser().parse("") is None
        assert SyslogParser().parse("   ") is None

    def test_non_matching_returns_none(self):
        assert SyslogParser().parse("not a syslog line at all") is None
        assert SyslogParser().parse("12345 random text") is None

    def test_valid_with_priority_and_pid(self):
        result = SyslogParser().parse(_WITH_PRIORITY_PID)
        assert result is not None
        assert result["priority"] == "34"
        assert result["month"] == "Jan"
        assert result["day"] == "5"
        assert result["time"] == "06:00:00"
        assert result["hostname"] == "mymachine"
        assert result["process"] == "su"
        assert result["pid"] == "1234"
        assert "su root" in result["message"]

    def test_valid_with_priority_no_pid(self):
        result = SyslogParser().parse(_WITH_PRIORITY_NO_PID)
        assert result is not None
        assert result["priority"] == "34"
        assert result["pid"] is None

    def test_valid_no_priority_with_pid(self):
        result = SyslogParser().parse(_NO_PRIORITY_WITH_PID)
        assert result is not None
        assert result["priority"] is None
        assert result["pid"] == "1234"

    def test_valid_no_priority_no_pid(self):
        result = SyslogParser().parse(_NO_PRIORITY_NO_PID)
        assert result is not None
        assert result["priority"] is None
        assert result["pid"] is None
        assert result["process"] == "sshd"

    def test_returns_dict(self):
        result = SyslogParser().parse(_NO_PRIORITY_NO_PID)
        assert isinstance(result, dict)

    def test_all_expected_keys_present(self):
        result = SyslogParser().parse(_WITH_PRIORITY_PID)
        for key in ("priority", "month", "day", "time",
                    "hostname", "process", "pid", "message"):
            assert key in result

    def test_leading_whitespace_stripped(self):
        result = SyslogParser().parse("   " + _NO_PRIORITY_NO_PID)
        assert result is not None


class TestSyslogParserBatch:

    def test_batch_mixed(self):
        parser = SyslogParser()
        lines = [_WITH_PRIORITY_PID, "bad line", _NO_PRIORITY_NO_PID, ""]
        successes, failures = parser.parse_batch(lines)
        assert len(successes) == 2
        assert len(failures) == 2