"""
Unit tests for core.pcap_parser.PcapCoreParser using stub mocks.
"""
import pytest
from unittest.mock import MagicMock, patch, mock_open
from core.pcap_parser import PcapCoreParser


class MockPkt:
    """Helper mock packet that simulates pyshark packet behavior."""
    def __init__(self, protocol, ip_src, ip_dst, status_code=None, method=None, details="",
                 imsi=None, msisdn=None, call_id=None):
        self._protocol = protocol
        self.ip = MagicMock(src=ip_src, dst=ip_dst)
        self.sniff_time = MagicMock()
        self.sniff_time.isoformat = lambda: "2026-07-28T10:00:00"
        self._status_code = status_code
        self._method = method
        self._details = details
        self.sip = MagicMock()
        self.http2 = MagicMock()
        if status_code:
            self.sip.response_code = status_code
            self.http2.headers_status = status_code
        if method:
            self.sip.method = method
        if details:
            self.sip.msg_body = details
        self.data = MagicMock()
        self._imsi = imsi
        self._msisdn = msisdn
        self._call_id = call_id
        if raw := self._raw_payload():
            self.data = raw

    def _raw_payload(self):
        parts = []
        if self._imsi:
            parts.append(f"IMSI={self._imsi}")
        if self._msisdn:
            parts.append(f"MSISDN={self._msisdn}")
        if self._call_id:
            parts.append(f"Call-ID={self._call_id}")
        if self._details:
            parts.append(self._details)
        return " | ".join(parts) if parts else None

    def __contains__(self, key):
        if key == "HTTP2" and self._protocol == "HTTP2":
            return True
        if key == "SIP" and self._protocol == "SIP":
            return True
        return False

    def __iter__(self):
        return iter([])


@pytest.fixture
def parser():
    return PcapCoreParser()


class TestPcapCoreParserExtraction:

    @patch("core.pcap_parser.os.path.exists", return_value=False)
    def test_extraer_eventos_sbi_missing_file_returns_empty(self, mock_exists, parser):
        result = parser.extraer_eventos_sbi("/nonexistent/trace.pcap")
        assert result == []

    @patch("core.pcap_parser.pyshark.FileCapture")
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_extraer_eventos_sbi_extracts_http2_events(self, mock_exists, mock_capture, parser):
        mock_pkt_http = MockPkt("HTTP2", "10.100.1.10", "10.100.1.30", status_code="404")
        mock_pkt_sip = MockPkt("SIP", "10.100.9.99", "10.200.1.1", status_code="403")

        mock_capture.return_value.__iter__ = lambda self: iter([mock_pkt_http, mock_pkt_sip])
        mock_capture.return_value.close = MagicMock()

        events = parser.extraer_eventos_sbi("fake.pcap")
        assert len(events) == 2

        assert events[0]["interface"] == "SBI"
        assert events[0]["http_status"] == "404"
        assert events[0]["source_nf"] == "10.100.1.10"
        assert events[0]["dest_nf"] == "10.100.1.30"

        assert events[1]["interface"] == "Gm/Mw"
        assert events[1]["http_status"] == "403"
        assert events[1]["source_nf"] == "10.100.9.99"
        assert events[1]["dest_nf"] == "10.200.1.1"

    @patch("core.pcap_parser.pyshark.FileCapture")
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_extraer_eventos_sbi_sip_invite_assigns_100(self, mock_exists, mock_capture, parser):
        mock_pkt = MockPkt("SIP", "10.100.9.99", "10.200.1.1", method="INVITE")
        mock_pkt.sip = MagicMock(spec=["method"])
        del mock_pkt.sip.response_code
        mock_pkt.sip.method = "INVITE"

        mock_capture.return_value.__iter__ = lambda self: iter([mock_pkt])
        mock_capture.return_value.close = MagicMock()

        events = parser.extraer_eventos_sbi("fake.pcap")
        assert len(events) == 1
        assert events[0]["http_status"] == "100"

    @patch("core.pcap_parser.pyshark.FileCapture")
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_extraer_eventos_sbi_falls_back_to_synthetic_when_empty(self, mock_exists, mock_capture, parser):
        mock_capture.return_value.__iter__ = lambda self: iter([])
        mock_capture.return_value.close = MagicMock()

        events = parser.extraer_eventos_sbi("empty.pcap")
        assert len(events) == 7
        assert all("timestamp" in e for e in events)

    @patch("core.pcap_parser.pyshark.FileCapture")
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_extraer_eventos_sbi_isc_interface_detection(self, mock_exists, mock_capture, parser):
        mock_pkt = MockPkt("SIP", "10.200.1.2", "10.200.8.8", status_code="200")

        mock_capture.return_value.__iter__ = lambda self: iter([mock_pkt])
        mock_capture.return_value.close = MagicMock()

        events = parser.extraer_eventos_sbi("fake.pcap")
        assert events[0]["interface"] == "ISC"

    @patch("core.pcap_parser.pyshark.FileCapture", side_effect=Exception("Capture error"))
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_extraer_eventos_sbi_handles_capture_exception_falls_back(self, mock_exists, mock_capture, parser):
        events = parser.extraer_eventos_sbi("broken.pcap")
        assert len(events) == 7

    @patch("core.pcap_parser.pyshark.FileCapture")
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_extraer_eventos_sbi_extracts_imsi_msisdn_from_payload(self, mock_exists, mock_capture, parser):
        mock_pkt = MockPkt("HTTP2", "10.100.9.99", "10.100.1.10", status_code="200",
                           imsi="2950112345678901234", msisdn="521234567890", call_id="abc123@ims")

        mock_capture.return_value.__iter__ = lambda self: iter([mock_pkt])
        mock_capture.return_value.close = MagicMock()

        events = parser.extraer_eventos_sbi("fake.pcap")
        assert len(events) == 1
        assert events[0]["imsi"] == "2950112345678901234"
        assert events[0]["msisdn"] == "521234567890"
        assert events[0]["call_id"] == "abc123@ims"

    @patch("core.pcap_parser.pyshark.FileCapture")
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_extraer_eventos_sbi_no_identity_returns_none(self, mock_exists, mock_capture, parser):
        mock_pkt = MockPkt("HTTP2", "10.100.1.10", "10.100.1.30", status_code="200")

        mock_capture.return_value.__iter__ = lambda self: iter([mock_pkt])
        mock_capture.return_value.close = MagicMock()

        events = parser.extraer_eventos_sbi("fake.pcap")
        assert len(events) == 1
        assert events[0]["imsi"] is None
        assert events[0]["msisdn"] is None
        assert events[0]["call_id"] is None

    @patch("core.pcap_parser.pyshark.FileCapture")
    @patch("core.pcap_parser.os.path.exists", return_value=True)
    def test_synthetic_fallback_includes_identity_fields(self, mock_exists, mock_capture, parser):
        mock_capture.return_value.__iter__ = lambda self: iter([])
        mock_capture.return_value.close = MagicMock()

        events = parser.extraer_eventos_sbi("empty.pcap")
        assert len(events) == 7
        for e in events:
            assert "imsi" in e
            assert "msisdn" in e
            assert "call_id" in e
            assert e["imsi"] is None
