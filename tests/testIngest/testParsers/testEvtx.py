# ==============================================================================
# tests/testIngest/testParsers/testEvtx.py
#
# Tests for loghunter/ingest/parsers/evtx.py
#
# Coverage — every branch:
#   None input → None
#   Blank input → None
#   Invalid XML → None
#   XML missing System element → None
#   XML missing EventID element → None
#   Valid XML minimal → dict with EventID
#   TimeCreated present → stored
#   TimeCreated absent → None
#   Computer present → stored
#   Computer absent → None
#   Channel present → stored
#   Channel absent → None
#   EventData with named Data elements → stored
#   EventData absent → not in result
#   Data element without Name attr → skipped
#   source_format → "evtx"
# ==============================================================================

from __future__ import annotations

import pytest

from loghunter.ingest.parsers.evtx import EVTXParser

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

def _wrap(system_inner: str, event_data: str = "") -> str:
    return f"""<Event xmlns="{_NS}">
  <System>
    {system_inner}
  </System>
  {event_data}
</Event>"""

_VALID_EVENT_ID = f'<EventID xmlns="{_NS}">4624</EventID>'
_VALID_TIME = f'<TimeCreated xmlns="{_NS}" SystemTime="2026-01-01T00:00:00Z"/>'
_VALID_COMPUTER = f'<Computer xmlns="{_NS}">WORKSTATION01</Computer>'
_VALID_CHANNEL = f'<Channel xmlns="{_NS}">Security</Channel>'

_FULL_SYSTEM = f"{_VALID_EVENT_ID}{_VALID_TIME}{_VALID_COMPUTER}{_VALID_CHANNEL}"

_FULL_EVENT_DATA = f"""<EventData xmlns="{_NS}">
  <Data Name="SubjectUserName">alice</Data>
  <Data Name="LogonType">3</Data>
  <Data>no name attr</Data>
</EventData>"""


class TestEVTXParserSourceFormat:

    def test_source_format_is_evtx(self):
        assert EVTXParser().source_format == "evtx"


class TestEVTXParserParse:

    def test_none_returns_none(self):
        assert EVTXParser().parse(None) is None

    def test_blank_returns_none(self):
        assert EVTXParser().parse("") is None
        assert EVTXParser().parse("   ") is None

    def test_invalid_xml_returns_none(self):
        assert EVTXParser().parse("<not valid xml") is None
        assert EVTXParser().parse("just a string") is None

    def test_xml_missing_system_returns_none(self):
        xml = f'<Event xmlns="{_NS}"><NoSystem/></Event>'
        assert EVTXParser().parse(xml) is None

    def test_xml_missing_event_id_returns_none(self):
        xml = _wrap("<NoEventID/>")
        assert EVTXParser().parse(xml) is None

    def test_minimal_valid_event_returns_dict(self):
        xml = _wrap(_VALID_EVENT_ID)
        result = EVTXParser().parse(xml)
        assert isinstance(result, dict)
        assert result["EventID"] == "4624"

    def test_time_created_stored_when_present(self):
        xml = _wrap(f"{_VALID_EVENT_ID}{_VALID_TIME}")
        result = EVTXParser().parse(xml)
        assert result["TimeCreated"] == "2026-01-01T00:00:00Z"

    def test_time_created_none_when_absent(self):
        xml = _wrap(_VALID_EVENT_ID)
        result = EVTXParser().parse(xml)
        assert result["TimeCreated"] is None

    def test_computer_stored_when_present(self):
        xml = _wrap(f"{_VALID_EVENT_ID}{_VALID_COMPUTER}")
        result = EVTXParser().parse(xml)
        assert result["Computer"] == "WORKSTATION01"

    def test_computer_none_when_absent(self):
        xml = _wrap(_VALID_EVENT_ID)
        result = EVTXParser().parse(xml)
        assert result["Computer"] is None

    def test_channel_stored_when_present(self):
        xml = _wrap(f"{_VALID_EVENT_ID}{_VALID_CHANNEL}")
        result = EVTXParser().parse(xml)
        assert result["Channel"] == "Security"

    def test_channel_none_when_absent(self):
        xml = _wrap(_VALID_EVENT_ID)
        result = EVTXParser().parse(xml)
        assert result["Channel"] is None

    def test_event_data_named_fields_stored(self):
        xml = _wrap(_FULL_SYSTEM, _FULL_EVENT_DATA)
        result = EVTXParser().parse(xml)
        assert result["SubjectUserName"] == "alice"
        assert result["LogonType"] == "3"

    def test_data_element_without_name_skipped(self):
        xml = _wrap(_FULL_SYSTEM, _FULL_EVENT_DATA)
        result = EVTXParser().parse(xml)
        # The nameless <Data> element should not create a None key
        assert None not in result

    def test_no_event_data_element_ok(self):
        xml = _wrap(_FULL_SYSTEM)
        result = EVTXParser().parse(xml)
        assert result is not None
        assert result["EventID"] == "4624"

    def test_full_event_all_fields(self):
        xml = _wrap(_FULL_SYSTEM, _FULL_EVENT_DATA)
        result = EVTXParser().parse(xml)
        assert result["EventID"] == "4624"
        assert result["TimeCreated"] == "2026-01-01T00:00:00Z"
        assert result["Computer"] == "WORKSTATION01"
        assert result["Channel"] == "Security"
        assert result["SubjectUserName"] == "alice"


class TestEVTXParserBatch:

    def test_batch_mixed_lines(self):
        parser = EVTXParser()
        valid = _wrap(_FULL_SYSTEM)
        lines = [valid, "bad xml", "", valid]
        successes, failures = parser.parse_batch(lines)
        assert len(successes) == 2
        assert len(failures) == 2