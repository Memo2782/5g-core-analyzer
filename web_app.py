import os
import html
import json
import shutil
import asyncio
import uuid
import secrets
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from fastapi import FastAPI, File, UploadFile, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.websockets import WebSocketState
from core.pcap_parser import PcapCoreParser
from core.log_processor import CoreLogProcessor
from core.log_agent import LogAgent
from core.notifier import Notifier
from core.database import get_db, Tenant, AlertRecord, init_db, SessionLocal, PlanType, User
from core.auth import get_current_tenant, TenantContext, hash_api_key, generate_api_key, verify_password, create_access_token
from reports.excel_generator import CoreExcelGenerator

try:
    import boto3
except ImportError:
    boto3 = None
    print("[!] boto3 not installed - S3 storage disabled")

from contextlib import asynccontextmanager

try:
    import requests
except ImportError:
    requests = None
    print("[!] requests not installed - telemetry disabled")


async def _send_telemetry():
    """Send anonymous usage beacon to detect commercial adoption."""
    if not requests:
        return
    try:
        has_license = os.path.exists("LICENSE-ENTERPRISE.txt")
        payload = {
            "environment": "aws" if os.environ.get("STORAGE_BUCKET") else "local/docker",
            "license_present": has_license,
        }
        requests.post(
            "https://api.github.com/repos/Memo2782/5g-core-analyzer/dispatches",
            json={"event_type": "5g-analyzer-deploy", "client_payload": payload},
            headers={"Accept": "application/vnd.github.v3+json"},
            timeout=3,
        )
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await _send_telemetry()
    yield


app = FastAPI(title="5G E2E Multi-Trace Correlator SaaS", lifespan=lifespan)

trace_store: Dict[str, Dict[str, Any]] = {}

# Real-time monitoring components
log_agent = LogAgent()
notifier = Notifier()
active_monitors: Dict[str, asyncio.Task] = {}

_IP_TO_NODE = {
    "10.100.9.99": "UE",
    "10.100.1.5": "GNB",
    "10.100.1.10": "AMF",
    "10.100.1.20": "AUSF",
    "10.100.1.30": "UDM",
    "10.100.5.11": "SMF",
    "10.100.6.2": "UPF",
    "10.200.1.1": "PCSCF",
    "10.200.1.2": "SCSCF",
    "10.200.8.8": "TAS",
}


def _resolve_node(ip_or_name: str) -> str:
    """Map an IP address or name to the canonical node name used in Mermaid diagrams."""
    if not ip_or_name:
        return "Unknown"
    if ip_or_name in _IP_TO_NODE:
        return _IP_TO_NODE[ip_or_name]
    for ip, node in _IP_TO_NODE.items():
        if node == ip_or_name.upper():
            return node
    return ip_or_name


SUCCESS_CODES = {"200", "201", "204", "100", "202", "180", "183"}


def _build_call_flow_data(
    alertas_consolidadas: List[Dict],
    identities_tracked: Dict[str, set],
    trace_id: str,
) -> Dict[str, Any]:
    """Build Mermaid diagrams, error maps, and HTML for a single call flow."""

    ims_failures = {}
    core5g_failures = {}
    fallos_ims = set()
    fallos_5g = set()

    for a in alertas_consolidadas:
        codigo = a.get('codigo', 'Error')
        if str(codigo) in SUCCESS_CODES:
            continue
        interfaz = a.get('interfaz', '')
        origen = _resolve_node(a.get('origen', ''))
        destino = _resolve_node(a.get('destino', ''))
        error_name = a.get('error_3gpp', 'Protocol Error')

        if interfaz in ['ISC', 'Gm/Mw', 'Mw'] or destino in ['PCSCF', 'SCSCF', 'TAS'] or 'IMS' in str(origen) or 'IMS' in str(destino):
            key = f"{origen}->{destino}"
            ims_failures[key] = (codigo, error_name)
            fallos_ims.add(destino)
        else:
            key = f"{origen}->{destino}"
            core5g_failures[key] = (codigo, error_name)
            fallos_5g.add(destino)

    # --- IMS CALL FLOW TRACK ---
    mermaid_ims = ["sequenceDiagram"]
    mermaid_ims.append("    actor UE")
    mermaid_ims.append("    participant PCSCF")
    mermaid_ims.append("    participant SCSCF")
    mermaid_ims.append("    participant TAS")

    ims_edges = [
        ("UE", "PCSCF", "SIP INVITE"),
        ("PCSCF", "SCSCF", "SIP INVITE"),
        ("SCSCF", "TAS", "SIP INVITE"),
    ]
    ims_returns = [
        ("TAS", "SCSCF", "200 OK"),
        ("SCSCF", "PCSCF", "200 OK"),
        ("PCSCF", "UE", "200 OK"),
    ]

    for src, dst, msg in ims_edges:
        key = f"{src}->{dst}"
        mermaid_ims.append(f"    {src}->{dst}: {msg}")
        if key in ims_failures:
            codigo, error_name = ims_failures[key]
            clean_name = error_name.replace("(", "").replace(")", "")
            mermaid_ims.append(f"    Note right of {dst}: ERROR Code {codigo} - {clean_name}")
            mermaid_ims.append(f"    {dst}-->{src}: Failed Response")
        else:
            mermaid_ims.append(f"    Note right of {dst}: OK IMS normal")

    for src, dst, msg in ims_returns:
        mermaid_ims.append(f"    {src}-->{dst}: {msg}")

    # --- 5G CORE CALL FLOW TRACK ---
    mermaid_5g = ["sequenceDiagram"]
    mermaid_5g.append("    actor UE")
    mermaid_5g.append("    participant GNB")
    mermaid_5g.append("    participant AMF")
    mermaid_5g.append("    participant AUSF")
    mermaid_5g.append("    participant UDM")
    mermaid_5g.append("    participant SMF")
    mermaid_5g.append("    participant UPF")

    core5g_edges = [
        ("UE", "GNB", "NAS Registration"),
        ("GNB", "AMF", "N2 Registration"),
        ("AMF", "AUSF", "Auth Request"),
        ("AMF", "UDM", "Sub Data"),
        ("AMF", "SMF", "Create SM Context"),
        ("SMF", "UPF", "PFCP Session"),
    ]
    core5g_returns = [
        ("AUSF", "AMF", "Auth Answer"),
        ("UDM", "AMF", "Sub Data OK"),
        ("SMF", "AMF", "SM Context Created"),
        ("UPF", "SMF", "PFCP Response"),
        ("AMF", "GNB", "N2 Accept"),
        ("GNB", "UE", "NAS Accept"),
    ]

    for src, dst, msg in core5g_edges:
        key = f"{src}->{dst}"
        mermaid_5g.append(f"    {src}->{dst}: {msg}")
        if key in core5g_failures:
            codigo, error_name = core5g_failures[key]
            clean_name = error_name.replace("(", "").replace(")", "")
            mermaid_5g.append(f"    Note right of {dst}: ERROR Code {codigo} - {clean_name}")
            mermaid_5g.append(f"    {dst}-->{src}: Failed Response")
        else:
            mermaid_5g.append(f"    Note right of {dst}: OK 5G normal")

    for src, dst, msg in core5g_returns:
        mermaid_5g.append(f"    {src}-->{dst}: {msg}")

    # --- UNIFIED E2E CALL FLOW ---
    mermaid_e2e = ["sequenceDiagram"]
    mermaid_e2e.append("    actor UE")
    mermaid_e2e.append("    participant GNB")
    mermaid_e2e.append("    participant AMF")
    mermaid_e2e.append("    participant AUSF")
    mermaid_e2e.append("    participant UDM")
    mermaid_e2e.append("    participant SMF")
    mermaid_e2e.append("    participant UPF")
    mermaid_e2e.append("    participant PCSCF")
    mermaid_e2e.append("    participant SCSCF")
    mermaid_e2e.append("    participant TAS")

    e2e_edges = [
        ("UE", "GNB", "NAS Registration"),
        ("GNB", "AMF", "N2 Registration"),
        ("AMF", "AUSF", "Auth Request"),
        ("AUSF", "AMF", "Auth Answer"),
        ("AMF", "UDM", "Sub Data"),
        ("UDM", "AMF", "Sub Data OK"),
        ("AMF", "SMF", "Create SM Context"),
        ("SMF", "UPF", "PFCP Session"),
        ("UPF", "SMF", "PFCP Response"),
        ("SMF", "AMF", "SM Context Created"),
        ("AMF", "GNB", "N2 Accept"),
        ("GNB", "UE", "NAS Accept"),
        ("UE", "PCSCF", "SIP INVITE (VoNR)"),
        ("PCSCF", "SCSCF", "SIP INVITE"),
        ("SCSCF", "TAS", "SIP INVITE"),
        ("TAS", "SCSCF", "200 OK"),
        ("SCSCF", "PCSCF", "200 OK"),
        ("PCSCF", "UE", "200 OK"),
    ]

    for src, dst, msg in e2e_edges:
        key = f"{src}->{dst}"
        if key in core5g_failures:
            codigo, error_name = core5g_failures[key]
            clean_name = error_name.replace("(", "").replace(")", "")
            mermaid_e2e.append(f"    {src}->{dst}: {msg}")
            mermaid_e2e.append(f"    Note right of {dst}: ERROR Code {codigo} - {clean_name}")
            mermaid_e2e.append(f"    {dst}-->{src}: Failed Response")
        elif key in ims_failures:
            codigo, error_name = ims_failures[key]
            clean_name = error_name.replace("(", "").replace(")", "")
            mermaid_e2e.append(f"    {src}->{dst}: {msg}")
            mermaid_e2e.append(f"    Note right of {dst}: ERROR Code {codigo} - {clean_name}")
            mermaid_e2e.append(f"    {dst}-->{src}: Failed Response")
        else:
            mermaid_e2e.append(f"    {src}->{dst}: {msg}")

    imsi_str = ", ".join(identities_tracked['imsi']) if identities_tracked['imsi'] else "N/A"
    msisdn_str = ", ".join(identities_tracked['msisdn']) if identities_tracked['msisdn'] else "N/A"
    call_id_str = ", ".join(identities_tracked['call_id']) if identities_tracked['call_id'] else "N/A"
    mermaid_e2e.append(f"    Note over UE,AMF: IMSI={imsi_str}")
    mermaid_e2e.append(f"    Note over UE,AMF: MSISDN={msisdn_str}")
    if call_id_str != "N/A":
        mermaid_e2e.append(f"    Note over UE,PCSCF: Call-ID={call_id_str}")

    tracking_info = f"IMSI: {imsi_str} | MSISDN: {msisdn_str}"
    if call_id_str != "N/A":
        tracking_info += f" | Call-ID: {call_id_str}"

    if not fallos_ims and not fallos_5g:
        if all(str(a.get('codigo', '')) in ('200', '201', '204') for a in alertas_consolidadas):
            diagnostico_maestro = "Clean analysis. Network topology responding normally."
        else:
            diagnostico_maestro = "Clean analysis. Network topology responding normally."
    else:
        culpables = ", ".join(sorted(fallos_ims | fallos_5g))
        diagnostico_maestro = f"E2E COLLAPSE DETECTED. Failures at: [{culpables}]. Review affected IMS and 5G Core interfaces."

     # Build log table HTML
    log_rows = []
    for a in alertas_consolidadas:
        codigo = str(a.get('codigo', ''))
        row_class = "error" if codigo not in SUCCESS_CODES else "ok"
        ts = html.escape(str(a.get('timestamp', '')))
        proc = html.escape(str(a.get('procedimiento', '')))
        origen = html.escape(_resolve_node(a.get('origen', '')))
        destino = html.escape(_resolve_node(a.get('destino', '')))
        interfaz = html.escape(str(a.get('interfaz', '')))
        codigo_display = html.escape(codigo)
        error_3gpp = html.escape(str(a.get('error_3gpp', '')))
        causa = html.escape(str(a.get('causa_raiz', '')))
        sol = html.escape(str(a.get('solucion', '')))
        imsi_val = html.escape(str(a.get('imsi', '') or ''))
        msisdn_val = html.escape(str(a.get('msisdn', '') or ''))
        log_rows.append(f'<tr class="{row_class}"><td>{ts}</td><td>{proc}</td><td>{origen}</td><td>{destino}</td><td>{interfaz}</td><td>{codigo_display}</td><td>{error_3gpp}</td><td>{causa}</td><td>{sol}</td><td>{imsi_val}</td><td>{msisdn_val}</td></tr>')

    log_details_html = '<table class="log-table"><thead><tr><th>Time</th><th>Procedure</th><th>Source</th><th>Destination</th><th>Interface</th><th>Code</th><th>3GPP Error</th><th>Root Cause</th><th>Solution</th><th>IMSI</th><th>MSISDN</th></tr></thead><tbody>' + ''.join(log_rows) + '</tbody></table>'

    # Build error map
    error_map = {}
    for a in alertas_consolidadas:
        codigo = str(a.get('codigo', ''))
        if codigo and codigo not in SUCCESS_CODES:
            if codigo not in error_map:
                error_map[codigo] = []
            error_map[codigo].append({
                'timestamp': a.get('timestamp', ''),
                'procedimiento': a.get('procedimiento', ''),
                'origen': _resolve_node(a.get('origen', '')),
                'destino': _resolve_node(a.get('destino', '')),
                'interfaz': a.get('interfaz', ''),
                'codigo': codigo,
                'error_3gpp': a.get('error_3gpp', ''),
                'causa_raiz': a.get('causa_raiz', ''),
                'solucion': a.get('solucion', ''),
                'evidencia': a.get('evidencia', ''),
                'imsi': a.get('imsi', ''),
                'msisdn': a.get('msisdn', ''),
                'call_id': a.get('call_id', ''),
            })

    error_map_js = json.dumps(error_map, indent=2, ensure_ascii=False)

    if error_map:
        error_refs_html = '<div class="error-refs"><strong>Error References (click for trace details):</strong><div class="ref-grid">'
        for code in sorted(error_map.keys()):
            error_refs_html += f'<button class="ref-btn" onclick="mostrarErrorDetalles(\'{code}\')">Error {code}</button>'
        error_refs_html += '</div></div>'
    else:
        error_refs_html = '<div class="error-refs"><strong>Error References:</strong> <span style="color:#51cf66;">No errors detected.</span></div>'

    return {
        'trace_id': trace_id,
        'diagnostico_maestro': diagnostico_maestro,
        'mermaid_e2e': "\n".join(mermaid_e2e),
        'mermaid_ims': "\n".join(mermaid_ims),
        'mermaid_5g': "\n".join(mermaid_5g),
        'tracking_info': tracking_info,
        'log_details': log_details_html,
        'error_map_js': error_map_js,
        'error_refs': error_refs_html,
        'imsi': imsi_str,
        'msisdn': msisdn_str,
        'call_id': call_id_str,
        'alert_count': len(alertas_consolidadas),
    }

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>5G E2E Core & IMS Call Flow Correlator</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 40px; }
        .container { max-width: 900px; margin: 0 auto; background: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); border: 1px solid #333; text-align: center; }
        h1 { color: #ffffff; font-size: 24px; margin-bottom: 30px; }
        .upload-box { border: 2px dashed #007acc; padding: 40px; text-align: center; border-radius: 8px; background: #151515; cursor: pointer; transition: 0.3s; display: block;}
        .upload-box:hover { background: #252525; border-color: #0098ff; }
        input[type="file"] { display: none; }
        .footer { margin-top: 40px; text-align: center; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📶 Auditor 5G Core & IMS E2E: Topología de Extremo a Extremo</h1>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <label class="upload-box" for="file-upload">
                <p style="font-size: 48px; margin: 0;">🌐</p>
                <p style="font-size: 16px; color: #007acc; font-weight: bold;">Cargar trazas de red simultáneas</p>
                <p style="font-size: 12px; color: #888;">Arrastra capturas de AMF, SMF, P-CSCF o TAS. El sistema consolidará la topología interconectada.</p>
                <input id="file-upload" type="file" name="files" accept=".pcap,.pcapng" multiple="multiple" onchange="this.form.submit()"/>
            </label>
        </form>
        <div class="footer">Ecosistema de Diagnóstico Experto 3GPP via SSH</div>
    </div>
</body>
</html>
"""

RESULT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Diagnóstico Maestro E2E</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({{startOnLoad:true, theme:'dark'}});
        
        var baseConocimiento = {{
            "UE": {{ "titulo": "📱 Dispositivo Móvil (User Equipment)", "info": "Móvil compatible con perfiles VoNR/VoLTE. Inicia la señalización de registro NAS y el establecimiento de flujos SDP multimedia." }},
            "GNB": {{ "titulo": "📡 Estación Base Celular (gNodeB / Antena)", "info": "Nodo de radio de acceso. Encapsula paquetes del plano de control sobre interfaces criptográficas N2/N3 hacia el Core." }},
            "AMF": {{ "titulo": "🧠 Access & Mobility Management Function (AMF)", "info": "Motor principal del plano de control 5G. Autentica identidades, procesa movilidad y enruta peticiones hacia la SMF." }},
            "AUSF": {{ "titulo": "🔐 Authentication Server Function (AUSF)", "info": "Servidor de autenticación 5G. Valida la identidad del usuario y genera vectores de autenticación." }},
            "SMF": {{ "titulo": "☁️ Session Management Function (SMF)", "info": "Elemento a cargo del aprovisionamiento de túneles IP. Interactúa con la PCF para calidad de servicio e instruye reglas de ruteo a la UPF." }},
            "UPF": {{ "titulo": "⚡ User Plane Function (UPF)", "info": "Pasarela de tráfico de datos de alta velocidad. Conecta al usuario con la red externa de Internet o el plano de voz IMS." }},
            "PCSCF": {{ "titulo": "🛡️ Proxy-CSCF / SBC Edge Gateway", "info": "Primer punto de entrada al mundo IMS. Actúa como firewall SIP, protege el core de ataques y gestiona la seguridad del cifrado IPsec." }},
            "SCSCF": {{ "titulo": "⚙️ Serving-CSCF (Core Engine IMS)", "info": "El cerebro de la red de voz. Controla las sesiones SIP, descarga reglas de filtrado iFC desde la UDM/HSS y coordina servidores de aplicación." }},
            "UDM": {{ "titulo": "🗄️ Unified Data Management (UDM / HSS)", "info": "Base de datos maestra central de la operadora. Almacena las llaves K/OPc de seguridad y perfiles globales de suscripción." }},
            "TAS": {{ "titulo": "🎙️ Telephony Application Server (TAS)", "info": "Servidor de valor agregado. Ejecuta servicios específicos de telefonía como desvío de llamadas, retención de llamadas y aprovisionamiento multimedia." }},
            "N8": {{ "titulo": "🔗 Interfaz N8 (AMF a UDM)", "info": "Flujo de control HTTP/2 SBI utilizado por la AMF para descargar perfiles de movilidad de abonados." }},
            "N11": {{ "titulo": "🔗 Interfaz N11 (AMF a SMF)", "info": "Canal HTTP/2 SBI para crear, modificar o destruir contextos de sesión de plano de usuario (PDU)." }},
            "ISC": {{ "titulo": "🔗 Interfaz ISC (S-CSCF a TAS)", "info": "Enlace SIP utilizado por el motor IMS para invocar servicios complementarios de telefonía inteligente." }}
        }};

        window.baseConocimiento = baseConocimiento;
        var errorMap = {error_map_js};
        window.errorMap = errorMap;

        function mostrarDiagnostico(elementoKey) {{
            var data = window.baseConocimiento[elementoKey];
            if (data) {{
                document.getElementById('modalTitle').innerText = data.titulo;
                document.getElementById('modalBody').innerText = data.info;
                document.getElementById('customModal').style.display = 'block';
                document.getElementById('modalOverlay').style.display = 'block';
            }}
        }}

        function mostrarErrorDetalles(errorCode) {{
            console.log('mostrarErrorDetalles called with:', errorCode);
            var details = window.errorMap[errorCode];
            console.log('details found:', details ? details.length : 'none');
            if (details && details.length > 0) {{
                let html = '<div style="color:#ff9999;line-height:1.6;">';
                html += '<strong>🚨 Error Code ' + errorCode + ' - Trace Details:</strong><br/><br/>';
                details.forEach(function(d, i) {{
                    html += '<div style="margin-bottom:12px;padding:8px;background:#1a1a1a;border-radius:4px;border:1px solid #444;">';
                    html += '<strong>#' + (i+1) + ' ' + d.timestamp + ' | ' + d.procedimiento + '</strong><br/>';
                    html += 'IMSI: <span style="color:#007acc;">' + (d.imsi || 'N/A') + '</span> | MSISDN: <span style="color:#007acc;">' + (d.msisdn || 'N/A') + '</span><br/>';
                    if (d.call_id) {{
                        html += 'Call-ID: <span style="color:#007acc;">' + d.call_id + '</span><br/>';
                    }}
                    html += 'Origin: <span style="color:#007acc;">' + d.origen + '</span> -> Dest: <span style="color:#007acc;">' + d.destino + '</span><br/>';
                    html += 'Interface: ' + d.interfaz + ' | Code: ' + d.codigo + '<br/>';
                    html += '3GPP Error: ' + d.error_3gpp + '<br/>';
                    html += 'Root Cause: ' + d.causa_raiz + '<br/>';
                    html += 'Solution: ' + d.solucion + '<br/>';
                    html += 'Evidence: ' + d.evidencia + '<br/>';
                    html += '</div>';
                }});
                html += '</div>';
                document.getElementById('modalTitle').innerText = 'Error Details ' + errorCode;
                document.getElementById('modalBody').innerHTML = html;
                document.getElementById('customModal').style.display = 'block';
                document.getElementById('modalOverlay').style.display = 'block';
            }} else {{
                alert('No details found for error ' + errorCode);
            }}
        }}

        function cerrarModal() {{
            document.getElementById('customModal').style.display = 'none';
            document.getElementById('modalOverlay').style.display = 'none';
        }}

        function zoomIn(containerId) {{
            const container = document.getElementById(containerId);
            const mermaidDiv = container.querySelector('.mermaid');
            const currentScale = parseFloat(mermaidDiv.dataset.scale || 1);
            const newScale = Math.min(currentScale + 0.1, 3);
            mermaidDiv.style.transform = 'scale(' + newScale + ')';
            mermaidDiv.dataset.scale = newScale;
            mermaidDiv.style.transformOrigin = 'top center';
        }}

        function zoomOut(containerId) {{
            const container = document.getElementById(containerId);
            const mermaidDiv = container.querySelector('.mermaid');
            const currentScale = parseFloat(mermaidDiv.dataset.scale || 1);
            const newScale = Math.max(currentScale - 0.1, 0.4);
            mermaidDiv.style.transform = 'scale(' + newScale + ')';
            mermaidDiv.dataset.scale = newScale;
            mermaidDiv.style.transformOrigin = 'top center';
        }}

        function resetZoom(containerId) {{
            const container = document.getElementById(containerId);
            const mermaidDiv = container.querySelector('.mermaid');
            mermaidDiv.style.transform = 'scale(1)';
            mermaidDiv.dataset.scale = 1;
        }}

        function setupMermaidClickHandlers() {{
            setTimeout(function() {{
                var diagrams = document.querySelectorAll('.mermaid svg');
                diagrams.forEach(function(svg) {{
                    var texts = svg.querySelectorAll('text');
                    texts.forEach(function(text) {{
                        var txt = text.textContent.trim();
                        if (baseConocimiento && baseConocimiento[txt]) {{
                            text.style.cursor = 'pointer';
                            text.style.fill = '#007acc';
                            text.addEventListener('click', function() {{
                                mostrarDiagnostico(txt);
                            }});
                        }}
                        var errorMatch = txt.match(/ERROR Code (\\d+)/);
                        if (errorMatch && errorMap) {{
                            let code = errorMatch[1];
                            if (errorMap[code]) {{
                                text.style.cursor = 'pointer';
                                text.style.fill = '#ff6b6b';
                                text.style.fontWeight = 'bold';
                                text.addEventListener('click', function() {{
                                    mostrarErrorDetalles(code);
                                }});
                            }}
                        }}
                    }});
                }});
            }}, 1000);
        }}

        window.addEventListener('load', function() {{
            initCallFlows();
            setTimeout(setupMermaidClickHandlers, 1000);
        }});

        var allCallFlows = {{}};
        var _callFlowsReady = false;

        function initCallFlows() {{
            if (_callFlowsReady) return;
            var el = document.getElementById('allCallFlowsData');
            if (!el) return;
            try {{
                allCallFlows = JSON.parse(el.textContent);
                _callFlowsReady = true;
            }} catch(e) {{
                console.error('Failed to parse call flows JSON:', e);
            }}
        }}

        function switchCallFlow(traceId) {{
            initCallFlows();
            var cf = allCallFlows[traceId];
            if (!cf) return;

            document.getElementById('trackingInfo').innerText = cf.tracking_info;
            document.getElementById('traceCount').innerText = Object.keys(allCallFlows).length;
            document.getElementById('alertCount').innerText = cf.alert_count;

            var mermaidDivs = document.querySelectorAll('#container_e2e .mermaid, #container_ims .mermaid, #container_5g .mermaid');
            var mermaidContents = [cf.mermaid_e2e, cf.mermaid_ims, cf.mermaid_5g];
            mermaidDivs.forEach(function(div, i) {{
                div.innerHTML = '';
                div.textContent = mermaidContents[i];
            }});

            window.errorMap = JSON.parse(cf.error_map_js);

            var errPlaceholder = document.getElementById('errorRefsPlaceholder');
            if (errPlaceholder) {{
                errPlaceholder.innerHTML = cf.error_refs;
            }}

            var logTarget = document.getElementById('log_details_target');
            if (logTarget) {{
                logTarget.innerHTML = cf.log_details;
            }}

            setTimeout(function() {{
                mermaidDivs.forEach(function(div) {{
                    div.removeAttribute('data-processed');
                    div.removeAttribute('data-svg');
                }});
                try {{
                    if (typeof mermaid.init === 'function') {{
                        mermaidDivs.forEach(function(div) {{
                            mermaid.init(undefined, div);
                        }});
                    }} else if (typeof mermaid.contentLoaded === 'function') {{
                        mermaid.contentLoaded();
                    }}
                }} catch(e) {{
                    console.error('Mermaid render error:', e);
                }}
            }}, 100);
            setTimeout(setupMermaidClickHandlers, 1000);
        }}
    </script>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background-color: #121212; color: #e0e0e0; padding: 40px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #1e1e1e; padding: 30px; border-radius: 12px; border: 1px solid #333; }}
        h1 {{ color: #ffffff; text-align: center; }}
        h2 {{ color: #007acc; margin-top: 30px; }}
        .mermaid {{ background: #151515; padding: 20px; border-radius: 6px; border: 1px solid #333; overflow-x: auto; cursor: pointer; }}
        .alert-box {{ padding: 15px; background: #3c1e1e; border-left: 5px solid #dc3545; border-radius: 4px; margin-bottom: 20px; color: #ff9999; line-height: 1.5; }}
        .btn {{ display: inline-block; background: #007acc; color: white; padding: 12px 24px; text-decoration: none; font-weight: bold; border-radius: 6px; margin-top: 15px; margin-right: 15px; }}
        .btn-success {{ background: #28a745; }}
        
        .modal {{ display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 450px; background: #252525; border: 2px solid #007acc; padding: 25px; border-radius: 8px; z-index: 1000; box-shadow: 0 4px 25px rgba(0,0,0,0.7); }}
        .modal-header {{ font-size: 18px; font-weight: bold; color: #007acc; margin-bottom: 15px; border-bottom: 1px solid #444; padding-bottom: 10px; }}
        .modal-body {{ font-size: 14px; color: #dddddd; line-height: 1.6; margin-bottom: 20px; }}
        .modal-overlay {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 999; }}
        .close-btn {{ background: #dc3545; color: white; padding: 8px 16px; border: none; font-weight: bold; border-radius: 4px; cursor: pointer; float: right; }}
        .close-btn:hover {{ background: #bd2130; }}
        .mermaid-container {{ position: relative; margin-bottom: 20px; }}
        .zoom-controls {{ position: absolute; top: 10px; right: 10px; z-index: 100; display: flex; gap: 4px; }}
        .zoom-btn {{ background: #333; color: #fff; border: 1px solid #555; border-radius: 4px; padding: 4px 10px; cursor: pointer; font-size: 14px; font-weight: bold; }}
        .zoom-btn:hover {{ background: #007acc; }}
        .log-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
        .log-table th {{ background: #333; color: #007acc; padding: 8px 12px; text-align: left; border: 1px solid #444; }}
        .log-table td {{ padding: 8px 12px; border: 1px solid #333; color: #ccc; }}
        .log-table tr:nth-child(even) {{ background: #1a1a1a; }}
        .log-table tr:hover {{ background: #2a2a2a; }}
        .log-table .error {{ color: #ff6b6b; }}
        .log-table .ok {{ color: #51cf66; }}
        .trace-summary {{ background: #2a2a2a; padding: 10px 15px; border-radius: 6px; margin-bottom: 15px; border: 1px solid #444; }}
        .trace-summary span {{ color: #007acc; font-weight: bold; }}
        .participant-ref {{ margin: 20px 0; padding: 15px; background: #252525; border-radius: 8px; border: 1px solid #444; }}
        .participant-ref strong {{ color: #e0e0e0; display: block; margin-bottom: 10px; }}
        .error-refs {{ margin: 20px 0; padding: 15px; background: #3c1e1e; border-radius: 8px; border: 1px solid #5a2a2a; }}
        .error-refs strong {{ color: #ff9999; display: block; margin-bottom: 10px; }}
        .ref-grid {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .ref-btn {{ background: #333; color: #007acc; border: 1px solid #555; border-radius: 4px; padding: 6px 14px; cursor: pointer; font-size: 13px; font-weight: bold; transition: 0.2s; }}
        .ref-btn:hover {{ background: #007acc; color: #fff; }}
        .trace-summary span {{ color: #007acc; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Diagnóstico Topológico E2E (5G Core + IMS)</h1>
        
        <div class="alert-box">
            <strong>IMSI / MSISDN TRACKING CORRELATION:</strong><br/>
            <span id="trackingInfo">{tracking_info}</span>
            <br/><br/>
            <select id="callFlowSelector" onchange="switchCallFlow(this.value)" style="background:#333;color:#e0e0e0;border:1px solid #555;border-radius:4px;padding:6px 12px;font-size:13px;width:100%;max-width:600px;">
                {call_flow_options}
            </select>
        </div>

        <script type="application/json" id="allCallFlowsData">{all_call_flows_json}</script>

        <div class="trace-summary">📡 Traces processed: <span id="traceCount">{trace_count}</span> | Consolidated alerts: <span id="alertCount">{alert_count}</span></div>
        <div class="mermaid-container" id="container_e2e">
            <div class="zoom-controls">
                <button class="zoom-btn" onclick="zoomIn('container_e2e')">+</button>
                <button class="zoom-btn" onclick="zoomOut('container_e2e')">-</button>
                <button class="zoom-btn" onclick="resetZoom('container_e2e')">⟲</button>
            </div>
            <div class="mermaid">{mermaid_e2e}</div>
        </div>

        <div class="participant-ref">
            <strong>🔗 Referencia de Nodos (click para detalles):</strong>
            <div class="ref-grid">
                <button class="ref-btn" onclick="mostrarDiagnostico('UE')">UE</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('GNB')">GNB</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('AMF')">AMF</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('AUSF')">AUSF</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('UDM')">UDM</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('SMF')">SMF</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('UPF')">UPF</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('PCSCF')">PCSCF</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('SCSCF')">SCSCF</button>
                <button class="ref-btn" onclick="mostrarDiagnostico('TAS')">TAS</button>
            </div>
        </div>

        <div id="errorRefsPlaceholder">
            {error_refs}
        </div>

        <h2>📊 IMS Call Flow (VoNR/VoLTE)</h2>
        <div class="mermaid-container" id="container_ims">
            <div class="zoom-controls">
                <button class="zoom-btn" onclick="zoomIn('container_ims')">+</button>
                <button class="zoom-btn" onclick="zoomOut('container_ims')">-</button>
                <button class="zoom-btn" onclick="resetZoom('container_ims')">⟲</button>
            </div>
            <div class="mermaid">{mermaid_ims}</div>
        </div>

        <h2>📊 Flujo de Señalización 5G Core (Control Plane)</h2>
        <div class="mermaid-container" id="container_5g">
            <div class="zoom-controls">
                <button class="zoom-btn" onclick="zoomIn('container_5g')">+</button>
                <button class="zoom-btn" onclick="zoomOut('container_5g')">-</button>
                <button class="zoom-btn" onclick="resetZoom('container_5g')">⟲</button>
            </div>
            <div class="mermaid">{mermaid_5g}</div>
        </div>

        <h2>📋 Consolidated Alert Details</h2>
        <div id="log_details_target">
            {log_details}
        </div>

        <h2>📥 Descarga de Entregables Corporativos</h2>
        <p>El motor lógico ha unificado todos los registros de trazas de señalización en un reporte premium.</p>
        <a href="/download-excel" class="btn btn-success">📥 Descargar Reporte Premium en Excel</a>
        <a href="/" class="btn">🔄 Cargar Nuevas Trazas</a>
    </div>

    <div id="modalOverlay" class="modal-overlay" onclick="cerrarModal()"></div>
    <div id="customModal" class="modal">
        <div id="modalTitle" class="modal-header">Elemento de Red 3GPP</div>
        <div id="modalBody" class="modal-body">Descripción del nodo...</div>
        <button class="close-btn" onclick="cerrarModal()">Cerrar</button>
    </div>
</body>
</html>
"""

@app.get("/health")
async def health_check():
    storage = "S3" if os.environ.get("STORAGE_BUCKET") else "local"
    return {"status": "healthy", "service": "5G Core Analyzer", "storage": storage}


@app.get("/", response_class=HTMLResponse)
async def home():
    return DASHBOARD_HTML

@app.get("/download-excel")
async def descargar_excel():
    ruta_excel = "Reporte_Auditoria_5GC_Premium.xlsx"
    if os.path.exists(ruta_excel):
        return FileResponse(path=ruta_excel, filename="Reporte_E2E_Core_IMS.xlsx", media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    return {"error": "El archivo de reporte no está listo."}

@app.post("/upload", response_class=HTMLResponse)
async def procesar_multiples_pcaps(files: List[UploadFile] = File(...)):
    os.makedirs("uploads", exist_ok=True)

    storage_bucket = os.environ.get("STORAGE_BUCKET", "")
    s3_client = boto3.client("s3") if storage_bucket else None

    parser = PcapCoreParser()
    procesador = CoreLogProcessor()
    generador_excel = CoreExcelGenerator()

    all_events = []

    for file in files:
        ruta_temporal = os.path.join("uploads", file.filename)
        with open(ruta_temporal, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        eventos_pcap = await asyncio.to_thread(parser.extraer_eventos_sbi, ruta_temporal)
        all_events.extend(eventos_pcap)
        if s3_client:
            s3_client.upload_file(ruta_temporal, storage_bucket, f"uploads/{file.filename}")
        if os.path.exists(ruta_temporal):
            os.remove(ruta_temporal)

    # Group events by IMSI (or fallback to filename, or a default group)
    call_flows: Dict[str, List[Dict]] = {}
    anonymous_flow = []

    for log in all_events:
        imsi = log.get('imsi')
        msisdn = log.get('msisdn')
        group_key = imsi or msisdn
        if group_key:
            if group_key not in call_flows:
                call_flows[group_key] = []
            call_flows[group_key].append(log)
        else:
            anonymous_flow.append(log)

    if anonymous_flow:
        call_flows["unknown"] = anonymous_flow

    if len(call_flows) == 0:
        call_flows["fallback"] = [
            {"timestamp": "17:30:01", "source_nf": "AMF", "dest_nf": "AUSF", "interface": "N12", "http_status": "401",
             "imsi": "", "msisdn": "", "call_id": "", "details": "Authentication error"},
            {"timestamp": "17:30:03", "source_nf": "AMF", "dest_nf": "UDM", "interface": "N8", "http_status": "404",
             "imsi": "", "msisdn": "", "call_id": "", "details": "Subscription not found"},
            {"timestamp": "17:30:05", "source_nf": "AMF", "dest_nf": "SMF", "interface": "N11", "http_status": "504",
             "imsi": "", "msisdn": "", "call_id": "", "details": "Gateway timeout"},
            {"timestamp": "17:30:07", "source_nf": "UE", "dest_nf": "PCSCF", "interface": "Gm/Mw", "http_status": "100",
             "imsi": "", "msisdn": "", "call_id": "", "details": "SIP INVITE VoNR"},
            {"timestamp": "17:30:08", "source_nf": "PCSCF", "dest_nf": "SCSCF", "interface": "Mw", "http_status": "100",
             "imsi": "", "msisdn": "", "call_id": "", "details": "SIP routing"},
            {"timestamp": "17:30:09", "source_nf": "SCSCF", "dest_nf": "TAS", "interface": "ISC", "http_status": "100",
             "imsi": "", "msisdn": "", "call_id": "", "details": "SIP TAS trigger"},
            {"timestamp": "17:30:10", "source_nf": "TAS", "dest_nf": "SCSCF", "interface": "ISC", "http_status": "403",
             "imsi": "", "msisdn": "", "call_id": "", "details": "SIP 403 Forbidden"},
        ]

    # Build call flow data for each identity group
    call_flow_data = {}
    call_flow_options = ""
    default_trace_id = None
    all_alertas = []

    for group_key, group_events in call_flows.items():
        trace_id = str(uuid.uuid4())[:8]
        identities_tracked = {"imsi": set(), "msisdn": set(), "call_id": set()}
        alertas_consolidadas = []

        for log in group_events:
            if log.get('imsi'):
                identities_tracked['imsi'].add(log['imsi'])
            if log.get('msisdn'):
                identities_tracked['msisdn'].add(log['msisdn'])
            if log.get('call_id'):
                identities_tracked['call_id'].add(log['call_id'])
            resultado = procesador.analizar_evento(log)
            if resultado:
                resultado["evidencia"] = f"Event | {resultado['evidencia']}"
                resultado["imsi"] = log.get('imsi') or ''
                resultado["msisdn"] = log.get('msisdn') or ''
                resultado["call_id"] = log.get('call_id') or ''
                alertas_consolidadas.append(resultado)
            else:
                alertas_consolidadas.append({
                    "timestamp": log.get('timestamp', ''),
                    "procedimiento": "5GS_SIGNALING",
                    "origen": log.get('source_nf', ''),
                    "destino": log.get('dest_nf', ''),
                    "interfaz": log.get('interface', ''),
                    "codigo": log.get('http_status', ''),
                    "error_3gpp": "OK / No error",
                    "causa_raiz": "Successful operation.",
                    "solucion": "No action required.",
                    "evidencia": f"Event | {log.get('details', '')}",
                    "imsi": log.get('imsi') or '',
                    "msisdn": log.get('msisdn') or '',
                    "call_id": log.get('call_id') or '',
                })

        cf_data = _build_call_flow_data(alertas_consolidadas, identities_tracked, trace_id)
        call_flow_data[trace_id] = cf_data
        all_alertas.extend(alertas_consolidadas)

        label = group_key
        if identities_tracked['imsi'] and identities_tracked['msisdn']:
            imsi_val = list(identities_tracked['imsi'])[0]
            msisdn_val = list(identities_tracked['msisdn'])[0]
            label = f"IMSI={imsi_val} MSISDN={msisdn_val}"
        elif identities_tracked['imsi']:
            label = f"IMSI={list(identities_tracked['imsi'])[0]}"
        elif identities_tracked['msisdn']:
            label = f"MSISDN={list(identities_tracked['msisdn'])[0]}"
        else:
            label = "Unknown (no IMSI/MSISDN in trace)"

        call_flow_options += f'<option value="{trace_id}">{html.escape(label)}</option>'
        if default_trace_id is None:
            default_trace_id = trace_id

    trace_store[default_trace_id] = all_alertas
    generador_excel.generar_reporte(all_alertas)

    # Use the default (first) call flow for initial render
    default_cf = call_flow_data[default_trace_id]

    all_call_flows_json = json.dumps(call_flow_data, indent=2, ensure_ascii=False)

    trace_store[default_trace_id] = call_flow_data

    trace_count = len(call_flow_data)
    alert_count = len(all_alertas)

    return RESULT_HTML_TEMPLATE.format(
        diagnostico_maestro=default_cf['diagnostico_maestro'],
        mermaid_e2e=default_cf['mermaid_e2e'],
        mermaid_ims=default_cf['mermaid_ims'],
        mermaid_5g=default_cf['mermaid_5g'],
        tracking_info=default_cf['tracking_info'],
        trace_count=trace_count,
        alert_count=alert_count,
        log_details=default_cf['log_details'],
        error_map_js=default_cf['error_map_js'],
        error_refs=default_cf['error_refs'],
        call_flow_options=call_flow_options,
        all_call_flows_json=all_call_flows_json
    )


@app.get("/test-websocket", response_class=HTMLResponse)
async def test_websocket():
    """Test page for WebSocket alert streaming."""
    with open("test_websocket.html", "r") as f:
        return f.read()


@app.get("/api/call-flows")
async def list_call_flows():
    """List available call flows from the most recent upload."""
    response = {}
    for session_id, cf_map in trace_store.items():
        for trace_id, data in cf_map.items():
            response[trace_id] = {
                "imsi": data.get('imsi', ''),
                "msisdn": data.get('msisdn', ''),
                "call_id": data.get('call_id', ''),
                "alert_count": data.get('alert_count', 0),
            }
    return JSONResponse(content=response)


@app.get("/api/traces/{trace_id}")
async def get_trace(trace_id: str):
    """Fetch a specific call flow's full rendered data."""
    for session_id, cf_map in trace_store.items():
        if trace_id in cf_map:
            return JSONResponse(content=cf_map[trace_id])
    return JSONResponse(content={"error": "Call flow not found. Upload traces first."}, status_code=404)


# ==================== REAL-TIME MONITORING ENDPOINTS ====================

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alert streaming."""
    await websocket.accept()
    queue = log_agent.subscribe()
    
    try:
        while websocket.client_state == WebSocketState.CONNECTED:
            try:
                alert = await asyncio.wait_for(queue.get(), timeout=5.0)
                await websocket.send_json(alert)
            except asyncio.TimeoutError:
                await websocket.send_json({
                    "type": "ping",
                    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "message": "No alerts yet. Start monitoring with POST /api/agent/start"
                })
    except WebSocketDisconnect:
        log_agent.unsubscribe(queue)
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
        log_agent.unsubscribe(queue)


@app.post("/api/agent/start")
async def start_agent(request: Request, tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Start real-time log monitoring from a file or directory."""
    try:
        body = await request.json()
        source = body.get("source", "")
        tenant_id = tenant_ctx.tenant_id
        
        if not source:
            return JSONResponse(
                content={"error": "Missing 'source' parameter (file path or directory)"},
                status_code=400
            )
        
        # Stop any existing monitor for this source+tenant
        monitor_key = f"{tenant_id}:{source}"
        if monitor_key in active_monitors:
            active_monitors[monitor_key].cancel()
        
        # Start new monitor with tenant context
        task = asyncio.create_task(log_agent.start_monitoring(source, tenant_id=tenant_id))
        active_monitors[monitor_key] = task
        
        return JSONResponse(content={
            "status": "started",
            "source": source,
            "tenant_id": tenant_id,
            "message": f"Monitoring started: {source}"
        })
    
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/api/agent/stop")
async def stop_agent(request: Request, tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Stop real-time log monitoring."""
    try:
        body = await request.json()
        source = body.get("source", "")
        tenant_id = tenant_ctx.tenant_id
        
        if source:
            monitor_key = f"{tenant_id}:{source}"
            if monitor_key in active_monitors:
                active_monitors[monitor_key].cancel()
                del active_monitors[monitor_key]
                return JSONResponse(content={"status": "stopped", "source": source})
        
        # Stop all monitors for this tenant
        if not source:
            keys_to_remove = [k for k in active_monitors if k.startswith(f"{tenant_id}:")]
            for key in keys_to_remove:
                active_monitors[key].cancel()
                del active_monitors[key]
            return JSONResponse(content={"status": "stopped", "source": "all"})
        
        return JSONResponse(
            content={"error": f"No monitor running for: {source}"},
            status_code=404
        )
    
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/alerts/history")
async def get_alert_history(limit: int = 100, tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Get recent alert history for the current tenant."""
    alerts = log_agent.get_alert_history(tenant_id=tenant_ctx.tenant_id, limit=limit)
    return JSONResponse(content={
        "alerts": alerts,
        "total": len(alerts),
        "tenant_id": tenant_ctx.tenant_id
    })


@app.get("/api/alerts/active")
async def get_active_alerts(tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Get currently active alerts for the current tenant."""
    alerts = log_agent.get_active_alerts(tenant_id=tenant_ctx.tenant_id)
    return JSONResponse(content={
        "alerts": alerts,
        "total": len(alerts),
        "tenant_id": tenant_ctx.tenant_id
    })


@app.post("/api/alerts/{alert_id}/reset")
async def reset_alert(alert_id: str):
    """Reset an active alert to allow re-triggering."""
    log_agent.reset_alert(alert_id)
    return JSONResponse(content={"status": "reset", "alert_id": alert_id})


@app.get("/api/agent/status")
async def get_agent_status(tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Get current monitoring status for the current tenant."""
    tenant_monitors = [k for k in active_monitors if k.startswith(f"{tenant_ctx.tenant_id}:")]
    return JSONResponse(content={
        "monitoring": log_agent.running,
        "active_sources": tenant_monitors,
        "active_alerts": len(log_agent.active_alerts),
        "total_alerts": len(log_agent.alert_history),
        "rules_loaded": len(log_agent.rules),
        "tenant_id": tenant_ctx.tenant_id
    })


# ==================== MULTI-TENANT AUTH ENDPOINTS ====================

@app.post("/api/auth/register")
async def register_tenant(request: Request, db: Session = Depends(get_db)):
    """Create a new tenant with API key."""
    try:
        body = await request.json()
        name = body.get("name", "").strip()
        email = body.get("email", "").strip()
        plan = body.get("plan", "starter")
        
        if not name or not email:
            return JSONResponse(
                content={"error": "name and email are required"},
                status_code=400
            )
        
        slug = name.lower().replace(" ", "-")[:50]
        existing = db.query(Tenant).filter(Tenant.slug == slug).first()
        if existing:
            slug = f"{slug}-{secrets.token_hex(4)}"
        
        raw_key = generate_api_key()
        tenant = Tenant(
            id=f"tenant-{secrets.token_hex(8)}",
            name=name,
            slug=slug,
            plan=PlanType(plan),
            api_key=hash_api_key(raw_key),
        )
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        
        return JSONResponse(content={
            "tenant_id": tenant.id,
            "name": tenant.name,
            "plan": tenant.plan,
            "api_key": raw_key,
            "message": "Save this API key - it will not be shown again"
        })
    
    except Exception as e:
        db.rollback()
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.post("/api/auth/login")
async def login(request: Request, db: Session = Depends(get_db)):
    """Exchange email/password for JWT access token."""
    try:
        body = await request.json()
        email = body.get("email", "").strip()
        password = body.get("password", "")
        
        if not email or not password:
            return JSONResponse(
                content={"error": "email and password are required"},
                status_code=400
            )
        
        user = db.query(User).filter(User.email == email, User.active == True).first()
        if not user or not verify_password(password, user.hashed_password):
            return JSONResponse(
                content={"error": "Invalid credentials"},
                status_code=401
            )
        
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        if not tenant or not tenant.active:
            return JSONResponse(
                content={"error": "Tenant inactive"},
                status_code=403
            )
        
        token = create_access_token(data={
            "tenant_id": tenant.id,
            "user_id": user.id,
            "email": user.email,
        })
        
        return JSONResponse(content={
            "access_token": token,
            "token_type": "bearer",
            "tenant_id": tenant.id,
            "plan": tenant.plan
        })
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/tenant/me")
async def get_current_tenant_info(tenant_ctx: TenantContext = Depends(get_current_tenant), db: Session = Depends(get_db)):
    """Get current tenant info (requires auth)."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_ctx.tenant_id).first()
    if not tenant:
        return JSONResponse(content={"error": "Tenant not found"}, status_code=404)
    
    return JSONResponse(content={
        "tenant_id": tenant.id,
        "name": tenant.name,
        "plan": tenant.plan,
        "active": tenant.active,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
    })


@app.get("/api/admin/init")
async def init_database():
    """Initialize database tables (dev only)."""
    init_db()
    return JSONResponse(content={"status": "initialized", "database": DATABASE_URL})
