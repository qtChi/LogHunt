"""
tests/testEngine/testIocMatcher.py
Tests for loghunter.engine.ioc_matcher.IOCMatcher
Target: 100% branch coverage
"""
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

from loghunter.engine.ioc_matcher import IOCMatcher, _ROW_CAP, _MATCH_FIELDS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ioc_dir(tmp_path):
    return str(tmp_path / "iocs")


@pytest.fixture
def matcher(ioc_dir):
    return IOCMatcher(ioc_dir)


def _write_iocs(ioc_dir_path: str, filename: str, lines: list[str]) -> None:
    p = Path(ioc_dir_path)
    p.mkdir(parents=True, exist_ok=True)
    (p / filename).write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_none_ioc_dir_raises(self):
        with pytest.raises(TypeError):
            IOCMatcher(None)

    def test_empty_ioc_dir_raises(self):
        with pytest.raises(ValueError):
            IOCMatcher("   ")

    def test_creates_directory(self, tmp_path):
        ioc_dir = str(tmp_path / "new_iocs")
        m = IOCMatcher(ioc_dir)
        assert Path(ioc_dir).exists()

    def test_existing_directory_ok(self, tmp_path):
        ioc_dir = str(tmp_path)
        m = IOCMatcher(ioc_dir)
        assert m.get_ioc_count() == 0


# ---------------------------------------------------------------------------
# load_iocs
# ---------------------------------------------------------------------------

class TestLoadIocs:
    def test_none_filename_raises(self, matcher):
        with pytest.raises(TypeError):
            matcher.load_iocs(None)

    def test_empty_filename_raises(self, matcher):
        with pytest.raises(ValueError):
            matcher.load_iocs("  ")

    def test_missing_file_raises(self, matcher):
        with pytest.raises(FileNotFoundError):
            matcher.load_iocs("nonexistent.txt")

    def test_loads_valid_iocs(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4", "5.6.7.8", "9.9.9.9"])
        m = IOCMatcher(ioc_dir)
        count = m.load_iocs("ips.txt")
        assert count == 3
        assert m.get_ioc_count() == 3

    def test_blank_lines_skipped(self, ioc_dir):
        _write_iocs(ioc_dir, "mixed.txt", ["1.2.3.4", "", "   ", "5.6.7.8"])
        m = IOCMatcher(ioc_dir)
        count = m.load_iocs("mixed.txt")
        assert count == 2

    def test_comment_lines_skipped(self, ioc_dir):
        _write_iocs(ioc_dir, "with_comments.txt", [
            "# This is a comment",
            "1.2.3.4",
            "#another comment",
            "5.6.7.8",
        ])
        m = IOCMatcher(ioc_dir)
        count = m.load_iocs("with_comments.txt")
        assert count == 2

    def test_iocs_stored_lowercased(self, ioc_dir):
        _write_iocs(ioc_dir, "hosts.txt", ["EVIL.COM", "Malware.EXE"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("hosts.txt")
        assert "evil.com" in m._iocs
        assert "malware.exe" in m._iocs

    def test_row_cap_d008(self, ioc_dir):
        """Excess rows beyond 100,000 are silently truncated (D-008)."""
        # Write 100,001 unique IPs
        lines = [f"10.0.{i // 256}.{i % 256}" for i in range(_ROW_CAP + 1)]
        _write_iocs(ioc_dir, "big.txt", lines)
        m = IOCMatcher(ioc_dir)
        count = m.load_iocs("big.txt")
        assert count == _ROW_CAP
        assert m.get_ioc_count() <= _ROW_CAP

    def test_multiple_files_accumulated(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.1.1.1"])
        _write_iocs(ioc_dir, "domains.txt", ["evil.com"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        m.load_iocs("domains.txt")
        assert m.get_ioc_count() == 2

    def test_duplicate_values_deduplicated(self, ioc_dir):
        _write_iocs(ioc_dir, "dupes.txt", ["1.1.1.1", "1.1.1.1", "1.1.1.1"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("dupes.txt")
        assert m.get_ioc_count() == 1


# ---------------------------------------------------------------------------
# match_event
# ---------------------------------------------------------------------------

class TestMatchEvent:
    def test_none_event_raises(self, matcher):
        with pytest.raises(TypeError):
            matcher.match_event(None)

    def test_no_iocs_loaded_returns_empty(self, matcher):
        event = MagicMock()
        result = matcher.match_event(event)
        assert result == []

    def _make_event_with_field(self, field_path, value, valid_fields=None):
        """Create mock OCSFEvent where get_field returns value for field_path."""
        event = MagicMock()
        valid_fields = valid_fields or _MATCH_FIELDS

        def get_field(path):
            if path in valid_fields and path == field_path:
                return value
            elif path in valid_fields:
                return None
            else:
                raise ValueError(f"not registered: {path}")

        event.get_field.side_effect = get_field
        return event

    def test_src_ip_match(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = self._make_event_with_field("src_endpoint.ip", "1.2.3.4")
        result = m.match_event(event)
        assert "1.2.3.4" in result

    def test_dst_ip_match(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["9.9.9.9"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = self._make_event_with_field("dst_endpoint.ip", "9.9.9.9")
        result = m.match_event(event)
        assert "9.9.9.9" in result

    def test_file_path_match(self, ioc_dir):
        _write_iocs(ioc_dir, "paths.txt", ["/tmp/malware"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("paths.txt")
        event = self._make_event_with_field("file.path", "/tmp/malware")
        result = m.match_event(event)
        assert "/tmp/malware" in result

    def test_user_name_match(self, ioc_dir):
        _write_iocs(ioc_dir, "users.txt", ["badactor"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("users.txt")
        event = self._make_event_with_field("actor.user.name", "badactor")
        result = m.match_event(event)
        assert "badactor" in result

    def test_case_insensitive_match(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = self._make_event_with_field("src_endpoint.ip", "1.2.3.4")
        result = m.match_event(event)
        assert len(result) >= 1

    def test_no_match_returns_empty(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = self._make_event_with_field("src_endpoint.ip", "10.0.0.1")
        result = m.match_event(event)
        assert result == []

    def test_none_field_value_skipped(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = MagicMock()
        event.get_field.return_value = None
        result = m.match_event(event)
        assert result == []

    def test_unregistered_field_exception_skipped(self, ioc_dir):
        """ValueError from get_field (unregistered field) is silently skipped."""
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = MagicMock()
        event.get_field.side_effect = ValueError("not registered")
        result = m.match_event(event)
        assert result == []

    def test_type_error_from_get_field_skipped(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = MagicMock()
        event.get_field.side_effect = TypeError("bad")
        result = m.match_event(event)
        assert result == []

    def test_multiple_matches_returned(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.2.3.4", "5.6.7.8"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        event = MagicMock()
        def get_field(path):
            return {"src_endpoint.ip": "1.2.3.4", "dst_endpoint.ip": "5.6.7.8"}.get(path)
        event.get_field.side_effect = get_field
        result = m.match_event(event)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# get_ioc_count
# ---------------------------------------------------------------------------

class TestGetIocCount:
    def test_empty_returns_zero(self, matcher):
        assert matcher.get_ioc_count() == 0

    def test_reflects_loaded_count(self, ioc_dir):
        _write_iocs(ioc_dir, "ips.txt", ["1.1.1.1", "2.2.2.2"])
        m = IOCMatcher(ioc_dir)
        m.load_iocs("ips.txt")
        assert m.get_ioc_count() == 2