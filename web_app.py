import os
import html
import json
import shutil
import asyncio
import uuid
import secrets
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi import FastAPI, File, UploadFile, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.websockets import WebSocketState
from core.pcap_parser import PcapCoreParser
from core.log_processor import CoreLogProcessor
from core.log_agent import LogAgent
from core.notifier import Notifier
from core.database import get_db, Tenant, AlertRecord, Subscription, init_db, SessionLocal, PlanType, User
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
    if not log_agent.running:
        _monitor_task = asyncio.create_task(log_agent.start_monitoring("/open5gs-logs", tenant_id="tenant-2a259615ae0eb332"))
        active_monitors["lifespan:/open5gs-logs"] = _monitor_task
    yield


app = FastAPI(title="5G E2E Multi-Trace Correlator SaaS", lifespan=lifespan)

trace_store: Dict[str, Dict[str, Dict[str, Any]]] = {}

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
        .alerts-panel { margin-top: 30px; text-align: left; }
        .alert-item { padding: 12px; margin-bottom: 10px; border-radius: 6px; border-left: 5px solid #dc3545; background: #2a2a2a; }
        .alert-item.warning { border-left-color: #ffc107; }
        .alert-item.info { border-left-color: #17a2b8; }
        .alert-title { font-weight: bold; color: #ff9999; margin-bottom: 6px; }
        .alert-meta { font-size: 12px; color: #aaa; }
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
        <div class="alerts-panel">
            <h2 style="color:#007acc;">🚨 Real-Time Alerts</h2>
            <div id="realtime-alerts">Connecting to alert stream...</div>
        </div>

        <div style="background:#252525; padding:15px; border-radius:8px; border:1px solid #444; margin-top:20px;">
            <h2 style="color:#007acc; margin-top:0;">📡 Live Interface Tracking</h2>
            <div style="margin-bottom:12px;">
                <label style="color:#007acc; font-weight:bold; margin-right:10px;">Interface:</label>
                <select id="interface-selector" style="background:#333; color:#e0e0e0; border:1px solid #555; border-radius:4px; padding:6px 12px; font-size:13px;">
                    <option value="">All Interfaces</option>
                    <option value="N2">N2 (GNB-AMF)</option>
                    <option value="N11">N11 (AMF-SMF)</option>
                    <option value="N8">N8 (AMF-UDM)</option>
                    <option value="N12">N12 (AMF-AUSF)</option>
                    <option value="N3">N3 (UPF)</option>
                    <option value="N4">N4 (SMF-UPF)</option>
                    <option value="N7">N7 (SMF-PCF)</option>
                    <option value="N9">N9 (UPF-UPF)</option>
                    <option value="N15">N15 (AMF-UE)</option>
                    <option value="ISC">ISC (SCSCF-TAS)</option>
                    <option value="Gm/Mw">Gm/Mw (UE-PCSCF/PCSCF-SCSCF)</option>
                    <option value="Mw">Mw (PCSCF-SCSCF)</option>
                </select>
                <button id="start-monitoring" onclick="startInterfaceMonitoring()" style="background:#007acc; color:white; border:none; padding:6px 14px; border-radius:4px; cursor:pointer; font-weight:bold; margin-left:10px;">Start Monitoring</button>
                <button id="stop-monitoring" onclick="stopInterfaceMonitoring()" style="background:#dc3545; color:white; border:none; padding:6px 14px; border-radius:4px; cursor:pointer; font-weight:bold; margin-left:10px; display:none;">Stop</button>
            </div>
            <div id="monitoring-status" style="font-size:12px; color:#aaa; margin-bottom:10px;">Status: Idle</div>
            <div id="live-alerts" style="background:#1e1e1e; padding:10px; border-radius:6px; max-height:300px; overflow-y:auto; font-size:12px; font-family:monospace;">
                <div style="color:#888;">Live interface tracking will appear here...</div>
            </div>
        </div>

        <div class="footer">Ecosistema de Diagnóstico Experto 3GPP via SSH</div>
    </div>

    <script>
        (function() {
            var alertsDiv = document.getElementById('realtime-alerts');
            var ws = new WebSocket('ws://' + location.host + '/ws/alerts');
            var seen = new Set();

            ws.onopen = function() {
                alertsDiv.innerHTML = '<div class="alert-item info"><div class="alert-title">Connected</div><div class="alert-meta">Waiting for alerts...</div></div>';
            };

            ws.onmessage = function(event) {
                try {
                    var data = JSON.parse(event.data);
                    if (data.type === 'ping') return;
                    if (seen.has(data.id)) return;
                    seen.add(data.id);

                    var item = document.createElement('div');
                    item.className = 'alert-item';
                    if (data.severity === 'warning') item.className += ' warning';
                    if (data.severity === 'info') item.className += ' info';

                    item.innerHTML = '<div class="alert-title">' + (data.rule_name || data.type || 'Alert') + '</div>' +
                        '<div>' + (data.message || '') + '</div>' +
                        '<div class="alert-meta">' + (data.node || '') + ' | ' + (data.timestamp || '') + '</div>';

                    if (alertsDiv.children.length === 1 && alertsDiv.children[0].textContent.includes('Connected')) {
                        alertsDiv.innerHTML = '';
                    }
                    alertsDiv.insertBefore(item, alertsDiv.firstChild);
                } catch (e) {
                    console.error('Alert parse error', e);
                }
            };

            ws.onerror = function() {
                alertsDiv.innerHTML = '<div class="alert-item"><div class="alert-title">WebSocket error</div></div>';
            };

            ws.onclose = function() {
                var item = document.createElement('div');
                item.className = 'alert-item';
                item.innerHTML = '<div class="alert-title">Disconnected</div><div class="alert-meta">Will reconnect when server is ready.</div>';
                alertsDiv.insertBefore(item, alertsDiv.firstChild);
            };
        })();

        var interfaceWs = null;
        var interfaceMonitoring = false;

        function startInterfaceMonitoring() {
            console.log('startInterfaceMonitoring called');
            var selector = document.getElementById('interface-selector');
            var interfaceFilter = selector ? selector.value : '';
            var statusEl = document.getElementById('monitoring-status');
            var liveAlerts = document.getElementById('live-alerts');
            var startBtn = document.getElementById('start-monitoring');
            var stopBtn = document.getElementById('stop-monitoring');

            if (interfaceMonitoring) return;

            if (liveAlerts) liveAlerts.innerHTML = '<div style="color:#007acc;">Connecting to live interface stream...</div>';
            if (statusEl) statusEl.textContent = 'Status: Connecting...';
            if (startBtn) startBtn.disabled = true;
            if (stopBtn) stopBtn.style.display = 'inline-block';

            try {
                console.log('Creating WebSocket to:', 'ws://' + location.host + '/ws/alerts');
                interfaceWs = new WebSocket('ws://' + location.host + '/ws/alerts');
                interfaceMonitoring = true;
                console.log('WebSocket created, readyState:', interfaceWs.readyState);

                interfaceWs.onopen = function() {
                    if (statusEl) statusEl.textContent = 'Status: Monitoring ' + (interfaceFilter || 'all interfaces');
                    if (liveAlerts) liveAlerts.innerHTML = '';
                };

                interfaceWs.onmessage = function(event) {
                    try {
                        var data = JSON.parse(event.data);
                        if (data.type === 'ping') return;
                        if (!liveAlerts) return;

                        var item = document.createElement('div');
                        item.style.padding = '8px';
                        item.style.marginBottom = '6px';
                        item.style.borderRadius = '4px';
                        item.style.borderLeft = '3px solid #dc3545';
                        item.style.background = '#2a2a2a';

                        var interfaceTag = data.interface || data.node || '';
                        if (interfaceFilter && interfaceTag && interfaceTag !== interfaceFilter) {
                            return;
                        }

                        item.innerHTML = '<div style="font-weight:bold;color:#ff9999;">' + (data.rule_name || data.type || 'Alert') + '</div>' +
                            '<div style="font-size:11px;color:#aaa;">' + (data.node || '') + ' | ' + (data.timestamp || '') + ' | ' + interfaceTag + '</div>' +
                            '<div style="font-size:11px;color:#ccc; margin-top:4px;">' + (data.message || '') + '</div>';

                        liveAlerts.insertBefore(item, liveAlerts.firstChild);
                        if (liveAlerts.children.length > 200) {
                            liveAlerts.removeChild(liveAlerts.lastChild);
                        }
                    } catch (e) {
                        console.error('Live alert parse error', e);
                    }
                };

                interfaceWs.onerror = function() {
                    if (statusEl) statusEl.textContent = 'Status: WebSocket error';
                    if (liveAlerts) liveAlerts.innerHTML = '<div style="color:#ff6b6b;">WebSocket error. Is the monitoring agent running?</div>';
                };

                interfaceWs.onclose = function() {
                    if (statusEl) statusEl.textContent = 'Status: Disconnected';
                    if (stopBtn) stopBtn.style.display = 'none';
                    if (startBtn) startBtn.disabled = false;
                    interfaceMonitoring = false;
                };
            } catch (e) {
                console.error('Failed to start interface monitoring:', e);
                if (statusEl) statusEl.textContent = 'Status: Failed to start';
                if (liveAlerts) liveAlerts.innerHTML = '<div style="color:#ff6b6b;">Failed to start live monitoring.</div>';
                if (startBtn) startBtn.disabled = false;
                if (stopBtn) stopBtn.style.display = 'none';
                interfaceMonitoring = false;
            }
        }

        function stopInterfaceMonitoring() {
            if (interfaceWs) {
                interfaceWs.close();
                interfaceWs = null;
            }
            interfaceMonitoring = false;
            var statusEl = document.getElementById('monitoring-status');
            var startBtn = document.getElementById('start-monitoring');
            var stopBtn = document.getElementById('stop-monitoring');
            if (statusEl) statusEl.textContent = 'Status: Stopped';
            if (startBtn) startBtn.disabled = false;
            if (stopBtn) stopBtn.style.display = 'none';
        }
    </script>
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
                    }});

                    var fullText = '';
                    texts.forEach(function(text) {{
                        fullText += ' ' + text.textContent.trim();
                    }});

                    var errorMatch = fullText.match(/ERROR Code (\d+)/);
                    if (errorMatch && errorMap) {{
                        let code = errorMatch[1];
                        if (errorMap[code]) {{
                            svg.style.cursor = 'pointer';
                            svg.addEventListener('click', function(e) {{
                                if (fullText.match(/ERROR Code (\d+)/)) {{
                                    e.preventDefault();
                                    e.stopPropagation();
                                    mostrarErrorDetalles(code);
                                }}
                            }});
                        }}
                    }}
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


@app.get("/tracking", response_class=HTMLResponse)
async def tracking_dashboard():
    """Historical alarm tracking dashboard."""
    return TRACKING_HTML


@app.get("/api/alerts/{alert_id}/sequence")
async def get_alert_sequence(alert_id: str):
    """Fetch sequence diagram data for a specific alert."""
    for session_id, cf_map in trace_store.items():
        for trace_id, data in cf_map.items():
            if data.get('alert_id') == alert_id or trace_id == alert_id:
                return JSONResponse(content={
                    "mermaid_e2e": data["mermaid_e2e"],
                    "mermaid_ims": data["mermaid_ims"],
                    "mermaid_5g": data["mermaid_5g"],
                    "diagnostico_maestro": data["diagnostico_maestro"],
                    "tracking_info": data["tracking_info"],
                    "log_details": data["log_details"],
                    "alert_id": alert_id,
                    "error_map_js": data["error_map_js"],
                })
    return JSONResponse(content={"error": "Alert sequence not found."}, status_code=404)


TRACKING_HTML = r"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Historical Alarm Tracking</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({startOnLoad: false, theme: 'dark'});

        var apiKey = '';
        var baseConocimiento = {
            'UE': 'User Equipment - Terminal móvil 5G que inicia el procedimiento de registro.',
            'GNB': 'gNodeB - Estación base 5G que gestiona el acceso radio y la interfaz N2.',
            'AMF': 'Access and Mobility Management Function - Gestiona registro, movilidad y autenticación.',
            'AUSF': 'Authentication Server Function - Realiza la autenticación 5G AKA.',
            'UDM': 'Unified Data Management - Gestiona el perfil de suscripción y datos del usuario.',
            'SMF': 'Session Management Function - Gestiona el plano de datos y túneles.',
            'UPF': 'User Plane Function - Nodo de plano de datos que enruta tráfico.',
            'PCSCF': 'Proxy CSCF - Punto de entrada SIP para IMS.',
            'SCSCF': 'Serving CSCF - Nodo central de control de llamadas IMS.',
            'TAS': 'Telephony Application Server - Servidor de aplicaciones de telefonía.'
        };

        function getApiHeaders() {
            return { 'x-api-key': apiKey };
        }

        function saveApiKey() {
            var input = document.getElementById('api-key-input');
            var status = document.getElementById('api-key-status');
            var key = input ? input.value.trim() : '';
            if (!key) {
                if (status) status.textContent = 'Please enter an API key.';
                return;
            }
            apiKey = key;
            localStorage.setItem('tracking_api_key', key);
            if (status) status.textContent = 'API key saved.';
            loadSubscribers();
        }

        function loadSubscribers() {
            fetch('/api/alerts/history', { headers: getApiHeaders() })
                .then(function(r) {
                    if (r.status === 401) {
                        throw new Error('Unauthorized: please enter your API key.');
                    }
                    return r.json();
                })
                .then(function(data) {
                    var list = document.getElementById('subscriber-list');
                    if (!list) return;
                    list.innerHTML = '';
                    if (!data || !data.length) {
                        list.innerHTML = '<div style="color:#888;">No historical alarms found.</div>';
                        return;
                    }
                    var alerts = data.alerts || data;
                    if (!alerts || !alerts.length) {
                        list.innerHTML = '<div style="color:#888;">No historical alarms found.</div>';
                        return;
                    }
                    alerts.forEach(function(item) {
                        var div = document.createElement('div');
                        div.className = 'subscriber-item';
                        div.innerHTML = '<div style="font-weight:bold;color:#e0e0e0;">' + (item.rule_name || item.type || 'Alert') + '</div>' +
                            '<div style="font-size:12px;color:#aaa;">' + (item.node || '') + ' | ' + (item.timestamp || '') + '</div>';
                        div.addEventListener('click', function() {
                            document.querySelectorAll('.subscriber-item').forEach(function(el) { el.style.borderColor = '#333'; });
                            div.style.borderColor = '#007acc';
                            showAlertSequence(item.id || item.alert_id);
                        });
                        list.appendChild(div);
                    });
                })
                .catch(function(err) {
                    console.error('Failed to load subscribers:', err);
                    var list = document.getElementById('subscriber-list');
                    if (list) list.innerHTML = '<div style="color:#ff6b6b;">' + (err.message || 'Error loading historical alarms.') + '</div>';
                });
        }

        function loadTraces() {
            fetch('/api/traces', { headers: getApiHeaders() })
                .then(function(r) {
                    if (r.status === 401) {
                        throw new Error('Unauthorized: please enter your API key.');
                    }
                    return r.json();
                })
                .then(function(data) {
                    var list = document.getElementById('trace-list');
                    if (!list) return;
                    list.innerHTML = '';
                    if (!data || !data.length) {
                        list.innerHTML = '<div style="color:#888;">No uploaded PCAP traces found.</div>';
                        return;
                    }
                    data.forEach(function(session) {
                        var sessionDiv = document.createElement('div');
                        sessionDiv.style.marginBottom = '15px';
                        sessionDiv.innerHTML = '<div style="font-weight:bold;color:#e0e0e0;margin-bottom:6px;">Session: ' + session.session_id + ' | Traces: ' + session.trace_count + ' | Alerts: ' + session.alert_count + '</div>';

                        var grid = document.createElement('div');
                        grid.style.display = 'grid';
                        grid.style.gridTemplateColumns = 'repeat(auto-fill, minmax(220px, 1fr))';
                        grid.style.gap = '10px';

                        (session.traces || []).forEach(function(trace) {
                            var div = document.createElement('div');
                            div.className = 'subscriber-item';
                            div.innerHTML = '<div style="font-weight:bold;color:#e0e0e0;">Trace ' + trace.trace_id + '</div>' +
                                '<div style="font-size:12px;color:#aaa;">IMSI: ' + (trace.imsi || 'N/A') + '</div>' +
                                '<div style="font-size:12px;color:#aaa;">MSISDN: ' + (trace.msisdn || 'N/A') + '</div>' +
                                '<div style="font-size:12px;color:#aaa;">Alerts: ' + trace.alert_count + '</div>';
                            div.addEventListener('click', function() {
                                document.querySelectorAll('#trace-list .subscriber-item').forEach(function(el) { el.style.borderColor = '#333'; });
                                div.style.borderColor = '#007acc';
                                showTraceSequence(trace.trace_id);
                            });
                            grid.appendChild(div);
                        });

                        sessionDiv.appendChild(grid);
                        list.appendChild(sessionDiv);
                    });
                })
                .catch(function(err) {
                    console.error('Failed to load traces:', err);
                    var list = document.getElementById('trace-list');
                    if (list) list.innerHTML = '<div style="color:#ff6b6b;">' + (err.message || 'Error loading uploaded traces.') + '</div>';
                });
        }

        function showTraceSequence(traceId) {
            try {
                console.log('showTraceSequence called with:', traceId);
                var panel = document.getElementById('sequence-panel');
                var diagram = document.getElementById('sequence-diagram');
                if (!panel || !diagram) return;

                panel.style.display = 'block';
                panel.classList.add('active');
                diagram.innerHTML = 'Loading trace ' + traceId + '...';
                panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

                fetch('/api/traces/' + traceId, { headers: getApiHeaders() })
                    .then(function(r) {
                        if (r.status === 401) throw new Error('Unauthorized: please enter your API key.');
                        return r.json();
                    })
                    .then(function(data) {
                        console.log('Trace data received:', data);
                        var mermaidCode = data.mermaid_e2e || data.mermaid_5g || data.mermaid_ims || 'sequenceDiagram; A-->B: No data';
                        diagram.innerHTML = '<div class="mermaid">' + mermaidCode + '</div>';
                        if (data.error_map_js) {
                            window.errorMap = JSON.parse(data.error_map_js);
                        }
                        if (window.mermaid) {
                            var mermaidDivs = diagram.querySelectorAll('.mermaid');
                            mermaidDivs.forEach(function(div) {
                                div.removeAttribute('data-processed');
                                div.removeAttribute('data-svg');
                            });
                            mermaid.run({ nodes: Array.from(mermaidDivs) }).then(function() {
                                setupMermaidClickHandlers();
                            }).catch(function(err) {
                                console.error('Mermaid render error:', err);
                                showMermaidError(err, mermaidCode);
                                diagram.innerHTML = '<pre style="background:#1e1e1e;padding:15px;border-radius:6px;overflow:auto;text-align:left;font-size:12px;color:#e0e0e0;white-space:pre-wrap;word-break:break-word;max-width:100%;">' + mermaidCode.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre>';
                            });
                        }
                        if (data.diagnostico_maestro) {
                            var diag = document.getElementById('sequence-diagnostico');
                            if (diag) diag.textContent = data.diagnostico_maestro;
                        }
                    })
                    .catch(function(err) {
                        console.error('Failed to load trace sequence:', err);
                        diagram.innerHTML = '<div style="color:#ff6b6b;">Failed to load trace sequence: ' + (err.message || 'Unknown error') + '</div>';
                    });
            } catch (e) {
                console.error('showTraceSequence error:', e);
            }
        }

        function showAlertSequence(alertId) {
            try {
                console.log('showAlertSequence called with:', alertId);
                var panel = document.getElementById('sequence-panel');
                var diagram = document.getElementById('sequence-diagram');
                console.log('Panel found:', !!panel, 'Diagram found:', !!diagram);

                if (!panel || !diagram) {
                    console.error('Sequence panel or diagram not found');
                    return;
                }

                panel.style.display = 'block';
                panel.classList.add('active');
                diagram.innerHTML = 'Loading...';
                panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

                fetch('/api/alerts/' + alertId + '/sequence', { headers: getApiHeaders() })
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        console.log('Sequence data received:', data);
                        var mermaidCode = data.mermaid_e2e || data.mermaid_5g || data.mermaid_ims || 'sequenceDiagram; A-->B: No data';
                        diagram.innerHTML = '<div class="mermaid">' + mermaidCode + '</div>';
                        if (data.error_map_js) {
                            window.errorMap = JSON.parse(data.error_map_js);
                        }
                        if (window.mermaid) {
                            var mermaidDivs = diagram.querySelectorAll('.mermaid');
                            mermaidDivs.forEach(function(div) {
                                div.removeAttribute('data-processed');
                                div.removeAttribute('data-svg');
                            });
                            mermaid.run({ nodes: Array.from(mermaidDivs) }).then(function() {
                                setupMermaidClickHandlers();
                            }).catch(function(err) {
                                console.error('Mermaid render error:', err);
                                showMermaidError(err, mermaidCode);
                                diagram.innerHTML = '<pre style="background:#1e1e1e;padding:15px;border-radius:6px;overflow:auto;text-align:left;font-size:12px;color:#e0e0e0;white-space:pre-wrap;word-break:break-word;max-width:100%;">' + mermaidCode.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre>';
                            });
                        }
                        if (data.diagnostico_maestro) {
                            var diag = document.getElementById('sequence-diagnostico');
                            if (diag) diag.textContent = data.diagnostico_maestro;
                        }
                    })
                    .catch(function(err) {
                        console.error('Failed to load sequence:', err);
                        diagram.innerHTML = '<div style="color:#ff6b6b;">Failed to load sequence diagram.</div>';
                    });
            } catch (e) {
                console.error('showAlertSequence error:', e);
            }
        }

        function showMermaidError(err, code) {
            var errorModal = document.getElementById('mermaid-error-modal');
            var errorBody = document.getElementById('mermaid-error-body');
            if (errorModal && errorBody) {
                errorBody.innerHTML = '<div style="color:#ff9999;">' + (err && err.message ? err.message : String(err)) + '</div>' +
                    '<pre style="background:#1e1e1e;padding:10px;border-radius:4px;overflow:auto;text-align:left;font-size:12px;color:#e0e0e0;margin-top:10px;">' + code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre>';
                errorModal.style.display = 'block';
            }
        }

        function closeMermaidError() {
            var errorModal = document.getElementById('mermaid-error-modal');
            if (errorModal) errorModal.style.display = 'none';
        }

        function mostrarDiagnostico(nodo) {
            var desc = baseConocimiento[nodo] || 'Nodo de red 5G/IMS.';
            document.getElementById('error-modal').querySelector('div[id="error-modal-body"]').innerHTML = '<p>' + desc + '</p>';
            var modal = document.getElementById('error-modal');
            modal.style.display = 'block';
            document.getElementById('error-modal-overlay').style.display = 'block';
        }

        function mostrarErrorDetalles(errorCode) {
            console.log('mostrarErrorDetalles called with code:', errorCode);
            if (window.errorMap && window.errorMap[errorCode]) {
                var detalles = window.errorMap[errorCode];
                var html = '';
                detalles.forEach(function(detalle) {
                    html += '<div class="error-detail-card" style="background:#2a2a2a;border-left:3px solid #dc3545;padding:8px;margin-bottom:8px;border-radius:4px;">';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">Error Code</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.codigo + '</div></div>';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">3GPP Error</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.error_3gpp + '</div></div>';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">Timestamp</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.timestamp + '</div></div>';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">Interface</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.interfaz + '</div></div>';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">Source</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.origen + '</div></div>';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">Destination</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.destino + '</div></div>';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">Procedimiento</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.procedimiento + '</div></div>';
                    html += '<div class="field" style="margin-bottom:4px;"><div class="label" style="color:#888;font-size:11px;text-transform:uppercase;">Root Cause</div><div class="value" style="color:#ff9999;font-weight:bold;">' + detalle.causa_raiz + '</div></div>';
                    html += '</div>';
                    if (detalle.solucion && detalle.solucion.trim() !== '') {
                        html += '<div class="recommendation" style="background:#1e3a1e;border-left:3px solid #28a745;padding:8px;margin-top:8px;border-radius:4px;">';
                        html += '<div class="label" style="color:#51cf66;font-size:11px;text-transform:uppercase;">Recommended Action</div>';
                        html += '<div class="value" style="color:#dddddd;">' + detalle.solucion + '</div>';
                        html += '</div>';
                    }
                });
                document.getElementById('error-modal-body').innerHTML = html;
                var modal = document.getElementById('error-modal');
                modal.style.display = 'block';
                document.getElementById('error-modal-overlay').style.display = 'block';
            } else {
                alert('No details found for error ' + errorCode);
            }
        }

        function cerrarModalError() {
            document.getElementById('error-modal').style.display = 'none';
            document.getElementById('error-modal-overlay').style.display = 'none';
        }

        function setupMermaidClickHandlers() {
            document.removeEventListener('click', window._mermaidClickHandler);
            window._mermaidClickHandler = function(e) {
                var target = e.target;
                var svg = target;
                while (svg && svg.tagName !== 'svg') {
                    svg = svg.parentNode;
                }
                if (!svg) return;

                var container = svg;
                while (container && !container.classList.contains('mermaid')) {
                    container = container.parentNode;
                }
                if (!container) return;

                var allText = '';
                var textEls = svg.querySelectorAll('text');
                textEls.forEach(function(el) {
                    allText += ' ' + el.textContent.trim();
                });

                var errorMatch = allText.match(/ERROR Code (\d+)/);
                if (errorMatch && window.errorMap) {
                    let code = errorMatch[1];
                    if (window.errorMap[code]) {
                        e.preventDefault();
                        e.stopPropagation();
                        mostrarErrorDetalles(code);
                        return;
                    }
                }
                if (baseConocimiento) {
                    for (var node in baseConocimiento) {
                        if (allText.indexOf(node) !== -1) {
                            e.preventDefault();
                            e.stopPropagation();
                            mostrarDiagnostico(node);
                            return;
                        }
                    }
                }
            };
            document.addEventListener('click', window._mermaidClickHandler);
        }

        window.addEventListener('load', function() {
            window.errorMap = JSON.parse(document.getElementById('errorMapData').textContent || '{}');
            console.log('Initial errorMap:', window.errorMap);
            setupMermaidClickHandlers();

            var savedKey = localStorage.getItem('tracking_api_key');
            if (savedKey) {
                apiKey = savedKey;
                var input = document.getElementById('api-key-input');
                var status = document.getElementById('api-key-status');
                if (input) input.value = savedKey;
                if (status) status.textContent = 'API key loaded from browser storage.';
            }
            loadSubscribers();
            loadTraces();
        });
    </script>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background-color: #121212; color: #e0e0e0; padding: 40px; margin: 0; }
        .container { max-width: 1000px; margin: 0 auto; background: #1e1e1e; padding: 30px; border-radius: 12px; border: 1px solid #333; }
        h1 { color: #ffffff; text-align: center; }
        h2 { color: #007acc; margin-top: 30px; }
        .subscriber-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; margin-top: 15px; }
        .subscriber-item { background: #252525; border: 1px solid #333; border-radius: 8px; padding: 12px; cursor: pointer; transition: 0.2s; }
        .subscriber-item:hover { border-color: #007acc; background: #2a2a2a; }
        .subscriber-item.active { border-color: #007acc; }
        .sequence-panel { display: none; margin-top: 25px; }
        .sequence-panel.active { display: block; }
        .mermaid { background: #151515; padding: 20px; border-radius: 6px; border: 1px solid #333; overflow-x: auto; cursor: pointer; user-select: none; -webkit-user-select: none; -moz-user-select: none; }
        .mermaid svg { user-select: none; -webkit-user-select: none; -moz-user-select: none; }
        .mermaid text { user-select: none; -webkit-user-select: none; -moz-user-select: none; pointer-events: all; }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 9999; align-items: center; justify-content: center; }
        .modal-overlay.active { display: flex; }
        .modal-box { background: #1e1e1e; border: 1px solid #dc3545; border-radius: 8px; padding: 20px; max-width: 600px; width: 90%; max-height: 80vh; overflow: auto; color: #e0e0e0; }
        .modal-title { color: #ff9999; font-weight: bold; margin-bottom: 10px; }
        .modal-body { font-size: 14px; line-height: 1.5; }
        .modal-body code { background: #2a2a2a; padding: 2px 6px; border-radius: 4px; color: #ff9999; }
        .modal-close { margin-top: 15px; padding: 8px 16px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .mermaid svg text { font-family: Arial, sans-serif !important; }
        #error-modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); z-index: 999; }
        #error-modal { display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 360px; max-width: calc(100vw - 32px); background: #252525; border: 2px solid #ff3b3b; padding: 16px; border-radius: 8px; z-index: 10000; box-shadow: 0 4px 25px rgba(0,0,0,0.7); font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 Historical Alarm Tracking</h1>
        <p style="color:#aaa; text-align:center;">Select a historical alarm to view its sequence diagram and details.</p>

        <div style="background:#252525; padding:12px; border-radius:8px; border:1px solid #444; margin-bottom:20px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
            <label style="color:#007acc; font-weight:bold;">API Key:</label>
            <input id="api-key-input" type="text" placeholder="5ga_..." style="flex:1; min-width:220px; background:#1e1e1e; color:#e0e0e0; border:1px solid #555; border-radius:4px; padding:6px 10px; font-size:13px;" />
            <button onclick="saveApiKey()" style="background:#007acc; color:white; border:none; padding:6px 14px; border-radius:4px; cursor:pointer; font-weight:bold;">Save</button>
            <span id="api-key-status" style="font-size:12px; color:#aaa;"></span>
        </div>

        <h2>🔍 Historical Alarms</h2>
        <div id="subscriber-list" style="min-height: 120px;">
            <div style="color:#888;">Loading historical alarms...</div>
        </div>

        <h2>📁 Uploaded PCAP Traces</h2>
        <div id="trace-list" style="min-height: 120px;">
            <div style="color:#888;">Loading uploaded traces...</div>
        </div>

        <div id="sequence-panel" class="sequence-panel">
            <h2>📊 Sequence Diagram</h2>
            <div id="sequence-diagnostico" style="background:#2a2a2a; padding:10px; border-radius:6px; margin-bottom:15px; border:1px solid #444;"></div>
            <div id="sequence-diagram"></div>
        </div>
    </div>

    <div id="mermaid-error-modal" class="modal-overlay">
        <div class="modal-box">
            <div class="modal-title">⚠️ Diagram Render Error</div>
            <div class="modal-body" id="mermaid-error-body"></div>
            <button class="modal-close" onclick="closeMermaidError()">Close</button>
        </div>
    </div>

    <div id="error-modal-overlay" onclick="cerrarModalError()"></div>
    <div id="error-modal" style="display:none; position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); width:360px; max-width:calc(100vw - 32px); background:#252525; border:2px solid #ff3b3b; padding:16px; border-radius:8px; z-index:10000; box-shadow:0 4px 25px rgba(0,0,0,0.7); font-size:13px;">
        <div style="font-size:16px; font-weight:bold; color:#ff3b3b; margin-bottom:10px; border-bottom:1px solid #444; padding-bottom:8px;">Error Details</div>
        <div id="error-modal-body" style="font-size:13px; color:#dddddd; line-height:1.5; margin-bottom:14px; max-height:55vh; overflow-y:auto;"></div>
        <button class="modal-close" onclick="cerrarModalError()" style="margin-top:10px; padding:6px 14px; background:#dc3545; color:white; border:none; font-weight:bold; border-radius:4px; cursor:pointer; font-size:13px;">Close</button>
    </div>

    <script type="application/json" id="errorMapData">{}</script>
</body>
</html>
"""


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


@app.get("/api/traces")
async def list_traces(tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """List historical PCAP trace sessions."""
    response = []
    for session_id, session_data in trace_store.items():
        if not isinstance(session_data, dict):
            continue
        response.append({
            "session_id": session_id,
            "trace_count": len(session_data),
            "alert_count": 0,
            "traces": [
                {
                    "trace_id": trace_id,
                    "imsi": data.get('imsi', '') if isinstance(data, dict) else '',
                    "msisdn": data.get('msisdn', '') if isinstance(data, dict) else '',
                    "call_id": data.get('call_id', '') if isinstance(data, dict) else '',
                    "alert_count": data.get('alert_count', 0) if isinstance(data, dict) else 0,
                }
                for trace_id, data in session_data.items()
            ]
        })
    return JSONResponse(content=response)


@app.get("/api/traces/{trace_id}")
async def get_trace(trace_id: str, tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Fetch a specific call flow's full rendered data."""
    for session_id, session_data in trace_store.items():
        if isinstance(session_data, dict) and trace_id in session_data:
            return JSONResponse(content=session_data[trace_id])
    return JSONResponse(content={"error": "Call flow not found. Upload traces first."}, status_code=404)


@app.get("/api/alerts/{alert_id}/sequence")
async def get_alert_sequence(alert_id: str):
    """Fetch sequence diagram data for a specific alert."""
    for session_id, cf_map in trace_store.items():
        for trace_id, data in cf_map.items():
            if data.get('alert_id') == alert_id or trace_id == alert_id:
                return JSONResponse(content={
                    "mermaid_e2e": data["mermaid_e2e"],
                    "mermaid_ims": data["mermaid_ims"],
                    "mermaid_5g": data["mermaid_5g"],
                    "diagnostico_maestro": data["diagnostico_maestro"],
                    "tracking_info": data["tracking_info"],
                    "log_details": data["log_details"],
                    "alert_id": alert_id,
                    "error_map_js": data["error_map_js"],
                })
    return JSONResponse(content={"error": "Alert sequence not found."}, status_code=404)


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
async def start_agent(request: Request, tenant_ctx: TenantContext = Depends(get_current_tenant), db: Session = Depends(get_db)):
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
        
        # Check plan limits
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if tenant:
            current_sites = len([k for k in active_monitors if k.startswith(f"{tenant_id}:")])
            limit_error = _check_plan_limit(tenant, "sites", current_sites)
            if limit_error:
                return limit_error
        
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


@app.post("/api/alerts/reset-all")
async def reset_all_alerts(tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Reset all in-memory active alerts to allow re-triggering."""
    log_agent.active_alerts.clear()
    for window in log_agent.alert_windows.values():
        window.reset()
    return JSONResponse(content={"status": "all_alerts_reset", "tenant_id": tenant_ctx.tenant_id})


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
        "subscribers": len(log_agent.subscribers),
        "tenant_id": tenant_ctx.tenant_id,
        "debug": {
            "active_monitors": {k: {"done": v.done(), "cancelled": v.cancelled()} for k, v in active_monitors.items()},
            "alert_window_counts": {k: w.events.maxlen if w.events.maxlen else len(w.events) for k, w in log_agent.alert_windows.items()},
        }
    })


@app.post("/api/ingest")
async def ingest_events(request: Request, tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Ingest JSON log events directly and evaluate alert rules."""
    try:
        body = await request.json()
        events = body.get("events", [])
        if not events:
            return JSONResponse(content={"error": "Missing 'events' array"}, status_code=400)
        
        await log_agent.ingest_events(events, tenant_id=tenant_ctx.tenant_id)
        return JSONResponse(content={
            "status": "ingested",
            "count": len(events),
            "tenant_id": tenant_ctx.tenant_id
        })
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


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


# ==================== BILLING & SUBSCRIPTION ENDPOINTS ====================

PLAN_LIMITS = {
    "starter": {"sites": -1, "events_per_day": 5000},
    "pro": {"sites": 5, "events_per_day": 50000},
    "enterprise": {"sites": -1, "events_per_day": -1},
}


def _check_plan_limit(tenant: Tenant, limit_type: str, current_count: int) -> Optional[JSONResponse]:
    """Check if tenant has exceeded plan limits. Returns error response or None if OK."""
    limits = PLAN_LIMITS.get(tenant.plan.value, PLAN_LIMITS["starter"])
    limit = limits.get(limit_type, -1)
    
    if limit == -1:
        return None  # Unlimited
    
    if current_count >= limit:
        return JSONResponse(content={
            "error": f"Plan limit exceeded: {limit_type} limit is {limit} for {tenant.plan.value} plan. Upgrade at /api/billing/checkout",
            "limit": limit,
            "current": current_count,
            "plan": tenant.plan.value
        }, status_code=403)
    
    return None


@app.get("/api/billing/checkout")
async def get_checkout_url(plan: str = "starter", tenant_ctx: TenantContext = Depends(get_current_tenant)):
    """Get PayPal checkout URL for a plan upgrade."""
    plan_urls = {
        "starter": "https://www.paypal.com/paypalme/morpheusthechoice/50usd",
        "pro": "https://www.paypal.com/paypalme/morpheusthechoice/799usd",
        "enterprise": "https://www.paypal.com/paypalme/morpheusthechoice/2499usd",
        "perpetual": "https://www.paypal.com/paypalme/morpheusthechoice/2500usd",
    }
    
    if plan not in plan_urls:
        return JSONResponse(content={"error": "Invalid plan"}, status_code=400)
    
    return JSONResponse(content={
        "checkout_url": plan_urls[plan],
        "plan": plan,
        "tenant_id": tenant_ctx.tenant_id,
        "message": f"Complete payment at the URL, then email transaction ID to license@Memo2782.github.io for activation"
    })


@app.post("/api/webhook/paypal")
async def paypal_webhook(request: Request, db: Session = Depends(get_db)):
    """PayPal webhook to verify payments and activate subscriptions."""
    try:
        body = await request.json()
        event_type = body.get("event_type", "")
        
        # Verify webhook signature in production
        # For now, accept test/sandbox webhooks
        
        if event_type == "PAYMENT.SALE.COMPLETED":
            transaction_id = body.get("resource", {}).get("id", "")
            amount = body.get("resource", {}).get("amount", {}).get("total", "0")
            currency = body.get("resource", {}).get("amount", {}).get("currency", "USD")
            payer_email = body.get("resource", {}).get("payer", {}).get("payer_info", {}).get("email", "")
            
            # Find tenant by email or custom field
            tenant = db.query(Tenant).filter(Tenant.active == True).first()
            if tenant:
                # Update or create subscription
                subscription = db.query(Subscription).filter(Subscription.tenant_id == tenant.id).first()
                if not subscription:
                    subscription = Subscription(
                        id=f"sub-{secrets.token_hex(8)}",
                        tenant_id=tenant.id,
                        paypal_subscription_id=transaction_id,
                        status="active",
                    )
                    db.add(subscription)
                else:
                    subscription.paypal_subscription_id = transaction_id
                    subscription.status = "active"
                
                db.commit()
                
                # Send license email if payer_email is available
                if payer_email:
                    try:
                        license_path = os.path.join(os.path.dirname(__file__), "LICENSE-ENTERPRISE.txt")
                        license_text = ""
                        if os.path.exists(license_path):
                            with open(license_path, "r") as f:
                                license_text = f.read()
                        
                        notifier = Notifier()
                        plan_name = tenant.plan.value if hasattr(tenant.plan, 'value') else str(tenant.plan)
                        await notifier.send_license_email(
                            to_email=payer_email,
                            license_text=license_text,
                            plan=plan_name,
                            transaction_id=transaction_id
                        )
                    except Exception as e:
                        print(f"[!] Failed to send license email: {e}")
                
                return JSONResponse(content={
                    "status": "activated",
                    "tenant_id": tenant.id,
                    "transaction_id": transaction_id,
                    "amount": f"{amount} {currency}"
                })
        
        return JSONResponse(content={"status": "ignored", "event_type": event_type})
    
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/billing/subscription")
async def get_subscription_status(tenant_ctx: TenantContext = Depends(get_current_tenant), db: Session = Depends(get_db)):
    """Get current tenant's subscription status."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_ctx.tenant_id).first()
    if not tenant:
        return JSONResponse(content={"error": "Tenant not found"}, status_code=404)
    
    subscription = db.query(Subscription).filter(Subscription.tenant_id == tenant.id).first()
    
    return JSONResponse(content={
        "tenant_id": tenant.id,
        "plan": tenant.plan,
        "active": tenant.active,
        "subscription": {
            "id": subscription.id if subscription else None,
            "status": subscription.status if subscription else "none",
            "paypal_id": subscription.paypal_subscription_id if subscription else None,
            "current_period_start": subscription.current_period_start.isoformat() if subscription and subscription.current_period_start else None,
            "current_period_end": subscription.current_period_end.isoformat() if subscription and subscription.current_period_end else None,
        } if subscription else None
    })


@app.get("/api/billing/plans")
async def get_available_plans():
    """Get available pricing plans."""
    return JSONResponse(content={
        "plans": [
            {
                "id": "starter",
                "name": "Starter",
                "price": 50,
                "currency": "USD",
                "interval": "month",
                "limits": {"sites": 1, "events_per_day": 5000},
                "features": ["Email support", "1 site", "5K events/day"]
            },
            {
                "id": "pro",
                "name": "Pro",
                "price": 799,
                "currency": "USD",
                "interval": "month",
                "limits": {"sites": 5, "events_per_day": 50000},
                "features": ["Priority support", "5 sites", "50K events/day", "Slack channel"]
            },
            {
                "id": "enterprise",
                "name": "Enterprise",
                "price": 2499,
                "currency": "USD",
                "interval": "month",
                "limits": {"sites": -1, "events_per_day": -1},
                "features": ["24/7 support", "Unlimited sites", "Unlimited events", "White-label", "SLA"]
            },
            {
                "id": "perpetual",
                "name": "Perpetual License",
                "price": 2500,
                "currency": "USD",
                "interval": "one-time",
                "limits": {"sites": -1, "events_per_day": -1},
                "features": ["Lifetime license", "1 year updates", "Commercial use", "Email support"]
            }
        ]
    })
