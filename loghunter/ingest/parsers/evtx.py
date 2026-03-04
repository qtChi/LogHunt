# ==============================================================================
# loghunter/ingest/parsers/evtx.py
#
# EVTXParser — parses Windows Event Log (.evtx) files via python-evtx.
#
# Per spec section 9: returns None for records that cannot be parsed.
# Never raises on a single bad record.
#
# EVTX records are XML. Key fields extracted:
#   EventID, TimeCreated SystemTime, Computer, Channel,
#   SubjectUserName, SubjectUserSid, LogonType, IpAddress.
# ==============================================================================

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional

from loghunter.ingest.parsers.base import LogParser

# XML namespaces used in Windows Event Log records
_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event",
}


class EVTXParser(LogParser):
    """
    Parser for Windows Event Log XML records.

    Accepts raw XML strings as produced by python-evtx record.xml().
    """

    @property
    def source_format(self) -> str:
        return "evtx"

    def parse(self, raw_line: str) -> Optional[dict]:
        """
        Parse a single EVTX XML record string.

        Returns None for:
          - None input
          - Blank/whitespace input
          - Invalid XML
          - XML missing required System/EventID element

        Returns:
            Dict of extracted fields, or None.
        """
        if raw_line is None:
            return None

        line = raw_line.strip()
        if not line:
            return None

        try:
            root = ET.fromstring(line)
        except ET.ParseError:
            return None

        system = root.find("e:System", _NS)
        if system is None:
            return None

        event_id_el = system.find("e:EventID", _NS)
        if event_id_el is None:
            return None

        result: dict = {
            "EventID": event_id_el.text,
            "TimeCreated": None,
            "Computer": None,
            "Channel": None,
        }

        time_el = system.find("e:TimeCreated", _NS)
        if time_el is not None:
            result["TimeCreated"] = time_el.get("SystemTime")

        computer_el = system.find("e:Computer", _NS)
        if computer_el is not None:
            result["Computer"] = computer_el.text

        channel_el = system.find("e:Channel", _NS)
        if channel_el is not None:
            result["Channel"] = channel_el.text

        # Extract EventData key-value pairs
        event_data = root.find("e:EventData", _NS)
        if event_data is not None:
            for data_el in event_data.findall("e:Data", _NS):
                name = data_el.get("Name")
                if name:
                    result[name] = data_el.text

        return result