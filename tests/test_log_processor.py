"""
Unit tests for core.log_processor.CoreLogProcessor using stub mocks.
Includes contract-style verification against the 3GPP catalog.
"""
import pytest
import json
from unittest.mock import mock_open, patch
from core.log_processor import CoreLogProcessor


@pytest.fixture
def processor():
    return CoreLogProcessor()


class TestLogProcessorAnalysis:

    def test_analizar_evento_returns_none_for_empty_status(self, processor):
        log = {"source_nf": "AMF", "dest_nf": "UDM", "interface": "N8", "http_status": "", "details": "test"}
        result = processor.analizar_evento(log)
        assert result is None

    def test_analizar_evento_returns_none_for_missing_status(self, processor):
        log = {"source_nf": "AMF", "dest_nf": "UDM", "interface": "N8", "details": "test"}
        result = processor.analizar_evento(log)
        assert result is None

    def test_analizar_evento_maps_401_to_auth_error(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "AUSF",
            "interface": "N12",
            "http_status": "401",
            "details": "Auth failure trace",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert result["codigo"] == "401"
        assert "Autenticación" not in result["error_3gpp"] or "Unauthorized" in result["error_3gpp"] or "Protocol" in result["error_3gpp"]
        assert "Authentication" in result["causa_raiz"] or "K/OPc" in result["causa_raiz"]
        assert result["procedimiento"] == "5GS_SIGNALING"
        assert result["origen"] == "AMF"
        assert result["destino"] == "AUSF"

    def test_analizar_evento_maps_404_deep_nested(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "UDM",
            "interface": "N8",
            "http_status": "404",
            "details": "Subscription not found",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert result["codigo"] == "404"
        assert "Not Found" in result["causa_raiz"] or "Identity" in result["causa_raiz"]
        assert "NRF" in result["causa_raiz"]

    def test_analizar_evento_maps_504_core_timeout(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "SMF",
            "interface": "N11",
            "http_status": "504",
            "details": "Gateway timeout",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert result["codigo"] == "504"
        assert "latencia" in result["causa_raiz"].lower() or "timeout" in result["causa_raiz"].lower()
        assert "cascading" in result["causa_raiz"].lower()

    def test_analizar_evento_sip_403_forbidden(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "TAS",
            "dest_nf": "SCSCF",
            "interface": "ISC",
            "http_status": "403",
            "details": "Forbidden by TAS",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert result["codigo"] == "403"
        assert "Forbidden" in result["causa_raiz"] or "Subscription" in result["causa_raiz"]

    def test_analizar_evento_legacy_diameter_5001(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "MME",
            "dest_nf": "HSS",
            "interface": "S6a",
            "http_status": "5001",
            "details": "User unknown",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert result["codigo"] == "5001"
        assert result["procedimiento"] == "LEGACY_INTEROPERABILITY"

    def test_analizar_evento_unknown_code_falls_back_generic(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "SMF",
            "interface": "N11",
            "http_status": "418",
            "details": "I'm a teapot",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert result["codigo"] == "418"
        assert "catalogo" in result["error_3gpp"].lower() or "catalog" in result["error_3gpp"].lower()

    def test_analizar_evento_200_success_returns_none(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "UDM",
            "interface": "N8",
            "http_status": "200",
            "details": "Success",
        }
        result = processor.analizar_evento(log)
        assert result is None

    def test_analizar_evento_201_created_returns_none(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "SMF",
            "interface": "N11",
            "http_status": "201",
            "details": "Created",
        }
        result = processor.analizar_evento(log)
        assert result is None

    def test_analizar_evento_204_no_content_returns_none(self, processor):
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "SMF",
            "interface": "N11",
            "http_status": "204",
            "details": "No content",
        }
        result = processor.analizar_evento(log)
        assert result is None

    def test_analizar_evento_handles_flat_string_catalog(self, processor):
        """Test that flat string error descriptions in catalog are handled."""
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "AUSF",
            "interface": "N12",
            "http_status": "401",
            "details": "Flat string test",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert "Protocol Error" not in result["error_3gpp"] or result["error_3gpp"] == "Protocol Error"

    def test_analizar_evento_context_domain_tagging_legacy(self, processor):
        """Legacy 4G/3G/2G interfaces should be tagged as LEGACY_INTEROPERABILITY."""
        legacy_logs = [
            {"timestamp": "t", "source_nf": "MME", "dest_nf": "HSS", "interface": "S6a", "http_status": "5001", "details": "d"},
            {"timestamp": "t", "source_nf": "MSC", "dest_nf": "HLR", "interface": "SS7/MAP", "http_status": "13", "details": "d"},
        ]
        for log in legacy_logs:
            result = processor.analizar_evento(log)
            assert result is not None
            assert result["procedimiento"] == "LEGACY_INTEROPERABILITY"

    def test_analizar_evento_context_domain_tagging_5g(self, processor):
        """5G SBI interfaces should be tagged as 5GS_SIGNALING."""
        log = {
            "timestamp": "2026-07-28T10:00:00",
            "source_nf": "AMF",
            "dest_nf": "AUSF",
            "interface": "N12",
            "http_status": "401",
            "details": "Auth",
        }
        result = processor.analizar_evento(log)
        assert result is not None
        assert result["procedimiento"] == "5GS_SIGNALING"


class TestLogProcessorCatalogIntegrity:
    """Contract-style tests verifying the JSON catalog structure."""

    def test_catalog_has_expected_top_level_keys(self, processor):
        expected_keys = {"sbi_http_errors", "sbi_http_errors_5gs", "nas_mobility_errors_5gs",
                         "nas_session_errors_5gs", "ims_sip_errors",
                         "legacy_4g_nas_emm_emm", "legacy_4g_diameter_errors_s6a",
                         "legacy_2g_3g_map_errors_ss7", "fallas_nodos_5g"}
        actual_keys = set(processor.catalogo_3gpp.keys())
        assert expected_keys.issubset(actual_keys), f"Missing keys: {expected_keys - actual_keys}"

    def test_catalog_fallas_nodos_has_required_fields(self, processor):
        fallas = processor.catalogo_3gpp.get("fallas_nodos_5g", [])
        assert isinstance(fallas, list)
        assert len(fallas) > 0
        required_fields = {"procedimiento", "nodo_origen", "nodo_destino", "interfaz",
                           "codigo_http", "causa_nas", "error_3gpp", "causa_raiz", "solucion_L3"}
        for falla in fallas:
            missing = required_fields - set(falla.keys())
            assert not missing, f"Falla missing fields: {missing}"
