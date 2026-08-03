"""
Contract tests for web_app.py FastAPI endpoints.
These tests validate the API contract (GET /, POST /upload, GET /download-excel)
using stubbed parsers and processors so they don't depend on real PCAP files.
"""
import json
from io import BytesIO
from unittest.mock import MagicMock, patch, AsyncMock, mock_open
import pytest
from fastapi.testclient import TestClient

from web_app import app, RESULT_HTML_TEMPLATE


@pytest.fixture
def client():
    return TestClient(app)


STUB_EVENTS = [
    {"timestamp": "2026-07-31T12:00:00", "source_nf": "AMF", "dest_nf": "AUSF",
     "interface": "N12", "http_status": "401",
     "details": "Auth handshake failure trace"},
    {"timestamp": "2026-07-31T12:00:01", "source_nf": "AMF", "dest_nf": "UDM",
     "interface": "N8", "http_status": "404",
     "details": "SUPI not found in UDR"},
    {"timestamp": "2026-07-31T12:00:02", "source_nf": "AMF", "dest_nf": "SMF",
     "interface": "N11", "http_status": "504",
     "details": "Gateway timeout N11"},
    {"timestamp": "2026-07-31T12:00:03", "source_nf": "UE", "dest_nf": "PCSCF",
     "interface": "Gm/Mw", "http_status": "100",
     "details": "SIP INVITE VoNR call setup"},
    {"timestamp": "2026-07-31T12:00:04", "source_nf": "TAS", "dest_nf": "SCSCF",
     "interface": "ISC", "http_status": "403",
     "details": "MSISDN not provisioned for voice"},
]


@pytest.fixture
def stub_pcap_parser():
    """Stub PcapCoreParser that returns synthetic events."""
    with patch("web_app.PcapCoreParser") as MockParser:
        instance = MockParser.return_value
        instance.extraer_eventos_sbi = MagicMock(return_value=list(STUB_EVENTS))
        yield MockParser


@pytest.fixture
def stub_log_processor():
    """Stub CoreLogProcessor that passes through to real catalog."""
    with patch("web_app.CoreLogProcessor") as MockProc:
        instance = MockProc.return_value
        from core.log_processor import CoreLogProcessor
        real = CoreLogProcessor()
        instance.analizar_evento = real.analizar_evento
        yield MockProc


@pytest.fixture
def stub_excel_generator():
    """Stub CoreExcelGenerator to avoid file I/O."""
    with patch("web_app.CoreExcelGenerator") as MockGen:
        instance = MockGen.return_value
        instance.generar_reporte = MagicMock(return_value="Reporte_test.xlsx")
        yield MockGen


@patch("web_app.os.path.exists", return_value=False)
@patch("web_app.os.remove")
@patch("builtins.open", new_callable=mock_open)
def _upload_with_stub(mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator, filename="test_trace.pcap", content=b"fake pcap content"):
    """Helper to POST a fake file through the upload endpoint."""
    response = client.post(
        "/upload",
        files={"files": (filename, BytesIO(content), "application/octet-stream")},
    )
    return response


class TestHomePage:

    def test_get_home_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_home_contains_upload_form(self, client):
        response = client.get("/")
        assert 'action="/upload"' in response.text
        assert 'enctype="multipart/form-data"' in response.text
        assert 'accept=".pcap,.pcapng"' in response.text


class TestUploadEndpoint:

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_no_files_returns_422(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Upload with no files returns 422 - FastAPI requires at least one file."""
        response = client.post("/upload", files={})
        assert response.status_code == 422

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_with_stubbed_pcap_renders_diagnostic(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Full contract: upload a fake pcap file and verify HTML rendering."""
        response = client.post(
            "/upload",
            files={"files": ("test_trace.pcap", BytesIO(b"fake pcap content"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "sequenceDiagram" in response.text
        assert "5G" in response.text or "5GC" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_response_contains_mermaid_diagrams(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify both IMS and 5G Core mermaid diagrams are present."""
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake pcap content"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "sequenceDiagram" in response.text
        assert "<div class=\"mermaid\">" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_response_contains_error_refs(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify error reference buttons are rendered for non-200 codes."""
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake pcap content"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "error-refs" in response.text
        assert "mostrarErrorDetalles" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_response_contains_participant_ref_buttons(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify participant reference buttons are present."""
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake pcap content"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "participant-ref" in response.text
        assert "mostrarDiagnostico" in response.text
        assert "baseConocimiento" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_response_contains_modal(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify the modal structure is present."""
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake pcap content"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "customModal" in response.text
        assert "modalOverlay" in response.text
        assert "cerrarModal" in response.text


class TestDownloadEndpoint:

    def test_download_excel_returns_error_when_file_missing(self, client):
        with patch("web_app.os.path.exists", return_value=False):
            response = client.get("/download-excel")
            assert response.status_code == 200
            assert "error" in response.json()

    def test_download_excel_returns_file_when_exists(self, client):
        with patch("web_app.os.path.exists", return_value=True), \
             patch("web_app.FileResponse") as mock_response:
            mock_response.return_value = {"mock": "file"}
            response = client.get("/download-excel")
            assert response.status_code == 200


class TestMermaidGenerationContract:
    """Contract tests verifying Mermaid diagram structure."""

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_mermaid_ims_has_participants(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "participant PCSCF" in response.text
        assert "participant SCSCF" in response.text
        assert "participant TAS" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_mermaid_5g_has_participants(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "participant GNB" in response.text
        assert "participant AMF" in response.text
        assert "participant UPF" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_mermaid_error_notes_present(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify error notes appear in Mermaid when failures exist."""
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "Note right of" in response.text
        assert "ERROR Code" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_no_invalid_click_syntax_in_mermaid(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify no invalid 'click' statements appear in Mermaid diagram output only."""
        from io import BytesIO
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake"), "application/octet-stream")},
        )
        assert response.status_code == 200
        # Extract Mermaid blocks only - these should NOT contain 'click' directives
        # which are invalid in sequenceDiagram and cause "Syntax error in text"
        mermaid_blocks = [block for block in response.text.split('<div class="mermaid">')[1:]]
        for block in mermaid_blocks:
            mermaid_content = block.split("</div>")[0]
            assert "click " not in mermaid_content.lower(), \
                f"Invalid 'click' directive found in Mermaid: {mermaid_content[:200]}"

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_e2e_mermaid_contains_tracking_header(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify IMSI/MSISDN tracking header appears in the result page."""
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "MSISDN" in response.text or "IMSI" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_response_contains_call_flow_dropdown(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_pcap_parser, stub_log_processor, stub_excel_generator
    ):
        """Verify the call flow dropdown selector is present after upload."""
        response = client.post(
            "/upload",
            files={"files": ("test.pcap", BytesIO(b"fake"), "application/octet-stream")},
        )
        assert response.status_code == 200
        assert "callFlowSelector" in response.text
        assert "switchCallFlow" in response.text
        assert "allCallFlowsData" in response.text

    @patch("web_app.os.path.exists", return_value=False)
    @patch("web_app.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_upload_with_multiple_pcap_files_creates_multiple_call_flows(
        self, mock_open_fn, mock_remove, mock_exists, client, stub_log_processor, stub_excel_generator
    ):
        """Upload multiple fake PCAPs and verify the dropdown has multiple options."""
        multi_stub_events = [
            {"timestamp": "2026-07-31T12:00:00", "source_nf": "AMF", "dest_nf": "AUSF",
             "interface": "N12", "http_status": "401",
             "details": "Auth failure", "imsi": "001010000000001", "msisdn": "1555010001", "call_id": "1@ims.core.net"},
            {"timestamp": "2026-07-31T12:00:01", "source_nf": "AMF", "dest_nf": "UDM",
             "interface": "N8", "http_status": "404",
             "details": "Not found", "imsi": "001010000000002", "msisdn": "1555010002", "call_id": "2@ims.core.net"},
        ]
        with patch("web_app.PcapCoreParser") as MockParser:
            instance = MockParser.return_value
            instance.extraer_eventos_sbi = MagicMock(return_value=list(multi_stub_events))

            response = client.post(
                "/upload",
                files=[
                    ("files", ("trace1.pcap", BytesIO(b"fake1"), "application/octet-stream")),
                    ("files", ("trace2.pcap", BytesIO(b"fake2"), "application/octet-stream")),
                ],
            )
        assert response.status_code == 200
        import re
        opts = re.findall(r'<option value="([^"]+)">([^<]+)</option>', response.text)
        assert len(opts) >= 2
        labels = [label for _, label in opts]
        assert any("IMSI=001010000000001" in label for label in labels)
        assert any("IMSI=001010000000002" in label for label in labels)
