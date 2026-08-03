"""
Log generator for 5G Core + IMS tracing.

Generates multiple log formats suitable for tracking calls by MSISDN and IMSI:
  1. Syslog-style .log files (RFC 5424-like)
  2. Structured JSON logs
  3. Simulated SIP message logs (RFC 3261)
  4. HTTP/2 access logs (SBI interface)

Also generates PCAP files with embedded MSISDN/IMSI in packet payloads for
correlation testing.
"""
import json
import os
import random
from datetime import datetime, timedelta

from scapy.all import IP, TCP, UDP, Raw, wrpcap


class TrackedIdentity:
    """Immutable identity tracker for a single call/session."""
    def __init__(self, imsi: str, msisdn: str, impi: str = None):
        self.imsi = imsi
        self.msisdn = msisdn
        self.impi = impi or f"{msisdn}@scscf.ims.mnc01.mcc295.3gppnetwork.org"
        self.sip_call_id = f"{random.randint(100000, 999999)}@{random.choice(['scscf', 'pcscf', 'tas'])}.ims"
        self.pfcp_session_id = random.randint(10000000, 99999999)


NODE_IPS = {
    "AMF": "10.100.1.10",
    "AUSF": "10.100.1.20",
    "UDM": "10.100.1.30",
    "SMF": "10.200.5.11",
    "UPF": "10.200.5.20",
    "PCF": "10.200.5.50",
    "GNB": "10.100.0.2",
    "UE": "10.100.9.99",
    "PCSCF": "10.200.1.1",
    "SCSCF": "10.200.1.2",
    "TAS": "10.200.8.8",
}

NODE_PORTS = {
    "AMF": 80,
    "AUSF": 80,
    "UDM": 80,
    "SMF": 80,
    "UPF": 80,
    "PCF": 5000,
    "GNB": 3868,
    "UE": 5060,
    "PCSCF": 5060,
    "SCSCF": 5060,
    "TAS": 5060,
}


class LogGenerator:
    """Generates correlated logs and PCAP traces tracked by MSISDN/IMSI."""

    BASE_TIME = datetime.now()

    def __init__(self, output_dir: str = "data_samples"):
        self.output_dir = output_dir
        self.msisdn = None
        self.imsi = None
        self.identity = None
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_identity(self, msisdn: str = None, imsi: str = None) -> TrackedIdentity:
        """Generate or accept MSISDN/IMSI identity for correlation."""
        if msisdn is None:
            msisdn = f"52{random.randint(1000000000, 9999999999)}"
        if imsi is None:
            imsi = f"29501{random.randint(100000000000000, 999999999999999)}"
        self.msisdn = msisdn
        self.imsi = imsi
        self.identity = TrackedIdentity(imsi, msisdn)
        return self.identity

    def _ts(self, offset_seconds: float) -> str:
        dt = self.BASE_TIME + timedelta(seconds=offset_seconds)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(dt.microsecond/1000):03d}Z"

    # ------------------------------------------------------------------
    # Syslog-style logs (.log)
    # ------------------------------------------------------------------
    def generate_syslog(self, identity: TrackedIdentity, scenario: str = "success") -> str:
        """Generate a syslog-style .log file with MSISDN/IMSI tags."""
        lines = []
        t = 0.0

        lines.append(f"<165>1 {self._ts(t)} 5gc-host AMF - - "
                       f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                       f"NAS Registration Request received from UE (SUPI={identity.imsi})")
        t += 0.1

        lines.append(f"<165>1 {self._ts(t)} 5gc-host AMF - - "
                       f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                       f"N12 AUSF Authentication Request sent to {NODE_IPS['AUSF']}")
        t += 0.1

        if scenario == "auth_failed":
            lines.append(f"<133>1 {self._ts(t)} 5gc-host AMF - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                           f"AUSF Authentication Failure: HTTP 401 - K/OPc key mismatch")
        else:
            lines.append(f"<165>1 {self._ts(t)} 5gc-host AUSF - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                           f"N12 AUSF Authentication Success: HTTP 200")
        t += 0.1

        lines.append(f"<165>1 {self._ts(t)} 5gc-host AMF - - "
                       f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                       f"N8 UDM Subscription Data Get to {NODE_IPS['UDM']}")
        t += 0.1

        if scenario == "sub_not_found":
            lines.append(f"<133>1 {self._ts(t)} 5gc-host AMF - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                           f"UDM returned HTTP 404: SUPI not found in UDR")
        else:
            lines.append(f"<165>1 {self._ts(t)} 5gc-host UDM - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                           f"N8 UDM Subscription Data Response: HTTP 200 OK")
        t += 0.1

        lines.append(f"<165>1 {self._ts(t)} 5gc-host AMF - - "
                       f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                       f"N11 SMF Create SM Context Request sent")
        t += 0.1

        if scenario == "smf_timeout":
            lines.append(f"<134>1 {self._ts(t)} 5gc-host AMF - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                           f"SMF returned HTTP 504: Gateway Timeout on PDU Session Establishment")
        else:
            lines.append(f"<165>1 {self._ts(t)} 5gc-host SMF - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                           f"N11 SMF Create SM Context Response: HTTP 201 Created")
        t += 0.1

        lines.append(f"<165>1 {self._ts(t)} ims-host UE - - "
                       f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}][call-id:{identity.sip_call_id}] "
                       f"SIP INVITE sent to PCSCF - VoNR call setup initiated")
        t += 0.1

        if scenario == "ims_forbidden":
            lines.append(f"<134>1 {self._ts(t)} ims-host TAS - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}][call-id:{identity.sip_call_id}] "
                           f"SIP 403 Forbidden: MSISDN not provisioned for voice services in TAS DB")
        else:
            lines.append(f"<165>1 {self._ts(t)} ims-host TAS - - "
                           f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}][call-id:{identity.sip_call_id}] "
                           f"SIP 200 OK response from TAS - call connected")
        t += 0.1

        lines.append(f"<165>1 {self._ts(t)} 5gc-host UPF - - "
                       f"[imsi:{identity.imsi}][msisdn:{identity.msisdn}] "
                       f"N4 PFCP Session Establishment: pfcp_session_id={identity.pfcp_session_id} - media plane active")

        fname = os.path.join(self.output_dir, f"syslog_{scenario}_{identity.msisdn}.log")
        with open(fname, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"[loggen] Syslog written: {fname}")
        return fname

    # ------------------------------------------------------------------
    # JSON structured logs
    # ------------------------------------------------------------------
    def generate_json_logs(self, identity: TrackedIdentity, scenario: str = "success") -> str:
        """Generate structured JSON logs with IMSI/MSISDN correlation IDs."""
        records = []
        t = 0.0

        records.append({
            "timestamp": self._ts(t),
            "hostname": "5gc-amf-01",
            "log_source": "N1_NAS",
            "level": "INFO",
            "imsi": identity.imsi,
            "msisdn": identity.msisdn,
            "event": "REGISTRATION_REQUEST",
            "src_nf": "UE",
            "dst_nf": "AMF",
            "interface": "N1",
        })
        t += 0.05

        records.append({
            "timestamp": self._ts(t),
            "hostname": "5gc-amf-01",
            "log_source": "N12_HTTP2",
            "level": "INFO",
            "imsi": identity.imsi,
            "msisdn": identity.msisdn,
            "event": "AUTH_REQUEST",
            "src_nf": "AMF",
            "dst_nf": "AUSF",
            "interface": "N12",
            "http_status": 200 if scenario != "auth_failed" else 401,
        })
        t += 0.05

        records.append({
            "timestamp": self._ts(t),
            "hostname": "5gc-amf-01",
            "log_source": "N8_HTTP2",
            "level": "INFO" if scenario != "sub_not_found" else "ERROR",
            "imsi": identity.imsi,
            "msisdn": identity.msisdn,
            "event": "SUBSCRIPTION_DATA_GET",
            "src_nf": "AMF",
            "dst_nf": "UDM",
            "interface": "N8",
            "http_status": 200 if scenario != "sub_not_found" else 404,
        })
        t += 0.05

        records.append({
            "timestamp": self._ts(t),
            "hostname": "5gc-amf-01",
            "log_source": "N11_HTTP2",
            "level": "INFO" if scenario != "smf_timeout" else "ERROR",
            "imsi": identity.imsi,
            "msisdn": identity.msisdn,
            "event": "CREATE_SM_CONTEXT_REQUEST",
            "src_nf": "AMF",
            "dst_nf": "SMF",
            "interface": "N11",
            "http_status": 201 if scenario != "smf_timeout" else 504,
        })
        t += 0.05

        records.append({
            "timestamp": self._ts(t),
            "hostname": "ims-pcscf-01",
            "log_source": "IMS_SIP",
            "level": "INFO",
            "imsi": identity.imsi,
            "msisdn": identity.msisdn,
            "event": "SIP_INVITE",
            "src_nf": "UE",
            "dst_nf": "PCSCF",
            "interface": "Gm",
            "call_id": identity.sip_call_id,
            "method": "INVITE",
        })
        t += 0.05

        records.append({
            "timestamp": self._ts(t),
            "hostname": "ims-tas-01",
            "log_source": "IMS_SIP",
            "level": "ERROR" if scenario == "ims_forbidden" else "INFO",
            "imsi": identity.imsi,
            "msisdn": identity.msisdn,
            "event": "SIP_RESPONSE",
            "src_nf": "TAS",
            "dst_nf": "SCSCF",
            "interface": "ISC",
            "call_id": identity.sip_call_id,
            "http_status": 403 if scenario == "ims_forbidden" else 200,
            "reason": "Forbidden" if scenario == "ims_forbidden" else "OK",
        })
        t += 0.05

        records.append({
            "timestamp": self._ts(t),
            "hostname": "5gc-upf-01",
            "log_source": "N4_PFCP",
            "level": "INFO",
            "imsi": identity.imsi,
            "msisdn": identity.msisdn,
            "event": "PFCP_SESSION_ESTABLISHMENT",
            "src_nf": "SMF",
            "dst_nf": "UPF",
            "interface": "N4",
            "pfcp_session_id": identity.pfcp_session_id,
            "seid": identity.pfcp_session_id,
        })

        fname = os.path.join(self.output_dir, f"json_{scenario}_{identity.msisdn}.jsonl")
        with open(fname, "w") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"[loggen] JSON logs written: {fname}")
        return fname

    # ------------------------------------------------------------------
    # SIP message logs
    # ------------------------------------------------------------------
    def generate_sip_logs(self, identity: TrackedIdentity, scenario: str = "success") -> str:
        """Generate RFC 3261-style SIP message logs."""
        lines = []
        t = 0.0
        call_id = identity.sip_call_id

        lines.append(f"[{self._ts(t)}] ==> SIP REGISTER sent from UE to PCSCF")
        lines.append(f"    From: <sip:{identity.msisdn}@ims.mnc01.mcc295.3gppnetwork.org>")
        lines.append(f"    To: <sip:{identity.msisdn}@ims.mnc01.mcc295.3gppnetwork.org>")
        lines.append(f"    P-Asserted-Identity: <tel:{identity.msisdn}>")
        lines.append(f"    P-Access-Network-Identity: imsi-{identity.imsi}")
        t += 0.05

        lines.append(f"[{self._ts(t)}] ==> SIP INVITE sent from UE to PCSCF")
        lines.append(f"    From: <sip:{identity.msisdn}@ims.mnc01.mcc295.3gppnetwork.org>;tag={random.randint(100000,999999)}")
        lines.append(f"    To: <sip:1001@ims.mnc01.mcc295.3gppnetwork.org>")
        lines.append(f"    Call-ID: {call_id}")
        lines.append(f"    P-Charging-Vector: icid-value={identity.pfcp_session_id}; imsi={identity.imsi}")
        lines.append(f"    Content-Type: application/sdp")
        lines.append(f"    SDP: m=audio 50000 RTP/AVP 111 110 0 8")
        t += 0.05

        if scenario != "ims_forbidden":
            lines.append(f"[{self._ts(t)}] <== SIP 100 Trying from PCSCF to UE")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] ==> SIP INVITE forwarded from PCSCF to SCSCF")
            lines.append(f"    Call-ID: {call_id}")
            lines.append(f"    P-Charging-Vector: imsi={identity.imsi}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] ==> SIP INVITE forwarded from SCSCF to TAS")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] <== SIP 200 OK from TAS to SCSCF")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] <== SIP 200 OK from SCSCF to PCSCF")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] <== SIP 200 OK from PCSCF to UE")
            lines.append(f"    Call-ID: {call_id}")
        else:
            lines.append(f"[{self._ts(t)}] <== SIP 100 Trying from PCSCF to UE")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] ==> SIP INVITE forwarded from PCSCF to SCSCF")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] ==> SIP INVITE forwarded from SCSCF to TAS")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] <== SIP 403 Forbidden from TAS to SCSCF")
            lines.append(f"    Call-ID: {call_id}")
            lines.append(f"    Reason: Provisioning error - MSISDN {identity.msisdn} not found in TAS DB")
            t += 0.05
            lines.append(f"[{self._ts(t)}] <== SIP 403 Forbidden from SCSCF to PCSCF")
            lines.append(f"    Call-ID: {call_id}")
            t += 0.05
            lines.append(f"[{self._ts(t)}] <== SIP 403 Forbidden from PCSCF to UE")
            lines.append(f"    Call-ID: {call_id}")

        fname = os.path.join(self.output_dir, f"sip_{scenario}_{identity.msisdn}.log")
        with open(fname, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"[loggen] SIP logs written: {fname}")
        return fname

    # ------------------------------------------------------------------
    # HTTP/2 access logs (SBI)
    # ------------------------------------------------------------------
    def generate_http2_logs(self, identity: TrackedIdentity, scenario: str = "success") -> str:
        """Generate HTTP/2-style access logs for SBI interface tracking."""
        lines = []
        t = 0.0

        lines.append(f'{self._ts(t)} {NODE_IPS["UE"]}:{NODE_PORTS["UE"]} - - "POST /n1s/auth?imsi={identity.imsi}&msisdn={identity.msisdn} HTTP/2.0" '
                     f'{200 if scenario != "auth_failed" else 401} {random.randint(50,500)} "-" "UE_Agent"')
        t += 0.05

        lines.append(f'{self._ts(t)} {NODE_IPS["AMF"]}:{NODE_PORTS["AMF"]} - - "POST /n12/nausf-ueAuthentication?imsi={identity.imsi} HTTP/2.0" '
                     f'{200 if scenario != "auth_failed" else 401} {random.randint(100,400)} "-" "AMF_SBI_Client"')
        t += 0.05

        lines.append(f'{self._ts(t)} {NODE_IPS["AMF"]}:{NODE_PORTS["AMF"]} - - "GET /n8/nudm-sdm?supi={identity.imsi} HTTP/2.0" '
                     f'{200 if scenario != "sub_not_found" else 404} {random.randint(200,600)} "-" "AMF_SBI_Client"')
        t += 0.05

        lines.append(f'{self._ts(t)} {NODE_IPS["AMF"]}:{NODE_PORTS["AMF"]} - - "POST /n11/nsmf-pdusession?pfcp_session_id={identity.pfcp_session_id} HTTP/2.0" '
                     f'{201 if scenario != "smf_timeout" else 504} {random.randint(500,1200)} "-" "AMF_SBI_Client"')
        t += 0.05

        lines.append(f'{self._ts(t)} {NODE_IPS["UE"]}:{NODE_PORTS["UE"]} - - "INVITE sip:1001@ims.mnc01.mcc295.3gppnetwork.org SIP/2.0" '
                     f'{200 if scenario != "ims_forbidden" else 403} {random.randint(300,800)} "-" "SIP_Client/5.0"')
        lines.append(f'    P-Charging-Vector: imsi={identity.imsi}; msisdn={identity.msisdn}; call-id={identity.sip_call_id}')
        t += 0.05

        lines.append(f'{self._ts(t)} {NODE_IPS["TAS"]}:{NODE_PORTS["TAS"]} - - "INVITE sip:1001@ims.mnc01.mcc295.3gppnetwork.org SIP/2.0" '
                     f'{200 if scenario != "ims_forbidden" else 403} {random.randint(200,500)} "-" "TAS_Server/3.0"')
        lines.append(f'    P-Charging-Vector: imsi={identity.imsi}; msisdn={identity.msisdn}; call-id={identity.sip_call_id}')

        fname = os.path.join(self.output_dir, f"http2_{scenario}_{identity.msisdn}.log")
        with open(fname, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"[loggen] HTTP/2 logs written: {fname}")
        return fname

    # ------------------------------------------------------------------
    # PCAP with embedded IMSI/MSISDN
    # ------------------------------------------------------------------
    def generate_pcap(self, identity: TrackedIdentity, scenario: str = "success") -> str:
        """Generate a PCAP file with IMSI/MSISDN embedded in packet payloads."""
        packets = []

        payloads = {
            "success": [
                (NODE_IPS["UE"], NODE_IPS["AMF"], NODE_PORTS["UE"], NODE_PORTS["AMF"],
                 f"NAS Registration Request | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["AUSF"], NODE_PORTS["AMF"], NODE_PORTS["AUSF"],
                 f"HTTP/2 200 OK | Nausf_UEAuthentication | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["UDM"], NODE_PORTS["AMF"], NODE_PORTS["UDM"],
                 f"HTTP/2 200 OK | Nudm_SDM_Get | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["SMF"], NODE_PORTS["AMF"], NODE_PORTS["SMF"],
                 f"HTTP/2 201 Created | Nsmf_PDUSession | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["UE"], NODE_IPS["PCSCF"], NODE_PORTS["UE"], NODE_PORTS["PCSCF"],
                 f"SIP INVITE | Call-ID={identity.sip_call_id} | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["TAS"], NODE_IPS["SCSCF"], NODE_PORTS["TAS"], NODE_PORTS["SCSCF"],
                 f"SIP 200 OK | Call-ID={identity.sip_call_id} | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
            ],
            "auth_failed": [
                (NODE_IPS["UE"], NODE_IPS["AMF"], NODE_PORTS["UE"], NODE_PORTS["AMF"],
                 f"NAS Registration Request | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["AUSF"], NODE_PORTS["AMF"], NODE_PORTS["AUSF"],
                 f"HTTP/2 401 Unauthorized | Nausf_UEAuthentication | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
            ],
            "sub_not_found": [
                (NODE_IPS["UE"], NODE_IPS["AMF"], NODE_PORTS["UE"], NODE_PORTS["AMF"],
                 f"NAS Registration Request | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["AUSF"], NODE_PORTS["AMF"], NODE_PORTS["AUSF"],
                 f"HTTP/2 200 OK | Nausf_UEAuthentication | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["UDM"], NODE_PORTS["AMF"], NODE_PORTS["UDM"],
                 f"HTTP/2 404 Not Found | Nudm_SDM_Get | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
            ],
            "smf_timeout": [
                (NODE_IPS["UE"], NODE_IPS["AMF"], NODE_PORTS["UE"], NODE_PORTS["AMF"],
                 f"NAS Registration Request | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["AUSF"], NODE_PORTS["AMF"], NODE_PORTS["AUSF"],
                 f"HTTP/2 200 OK | Nausf_UEAuthentication | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["UDM"], NODE_PORTS["AMF"], NODE_PORTS["UDM"],
                 f"HTTP/2 200 OK | Nudm_SDM_Get | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["SMF"], NODE_PORTS["AMF"], NODE_PORTS["SMF"],
                 f"HTTP/2 504 Gateway Timeout | Nsmf_PDUSession | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
            ],
            "ims_forbidden": [
                (NODE_IPS["UE"], NODE_IPS["AMF"], NODE_PORTS["UE"], NODE_PORTS["AMF"],
                 f"NAS Registration Request | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["AUSF"], NODE_PORTS["AMF"], NODE_PORTS["AUSF"],
                 f"HTTP/2 200 OK | Nausf_UEAuthentication | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["UDM"], NODE_PORTS["AMF"], NODE_PORTS["UDM"],
                 f"HTTP/2 200 OK | Nudm_SDM_Get | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["AMF"], NODE_IPS["SMF"], NODE_PORTS["AMF"], NODE_PORTS["SMF"],
                 f"HTTP/2 201 Created | Nsmf_PDUSession | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["UE"], NODE_IPS["PCSCF"], NODE_PORTS["UE"], NODE_PORTS["PCSCF"],
                 f"SIP INVITE | Call-ID={identity.sip_call_id} | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
                (NODE_IPS["TAS"], NODE_IPS["SCSCF"], NODE_PORTS["TAS"], NODE_PORTS["SCSCF"],
                 f"SIP 403 Forbidden | Call-ID={identity.sip_call_id} | IMSI={identity.imsi} | MSISDN={identity.msisdn}"),
            ],
        }

        pkts_config = payloads.get(scenario, payloads["success"])
        for src_ip, dst_ip, sport, dport, payload_str in pkts_config:
            if dport == 5060:
                pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(load=payload_str.encode())
            else:
                pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport) / Raw(load=payload_str.encode())
            packets.append(pkt)

        fname = os.path.join(self.output_dir, f"trace_{scenario}_{identity.msisdn}.pcap")
        wrpcap(fname, packets)
        print(f"[loggen] PCAP written: {fname} ({len(packets)} packets)")
        return fname

    def generate_all(self, scenario: str = "success", msisdn: str = None, imsi: str = None):
        """Generate all log types for a single tracked identity."""
        if self.identity is None:
            self.generate_identity(msisdn, imsi)
        identity = self.identity

        print(f"\n[loggen] Generating logs for IMSI={identity.imsi}, MSISDN={identity.msisdn}, scenario={scenario}")
        results = {}
        results["pcap"] = self.generate_pcap(identity, scenario)
        results["syslog"] = self.generate_syslog(identity, scenario)
        results["json"] = self.generate_json_logs(identity, scenario)
        results["sip"] = self.generate_sip_logs(identity, scenario)
        results["http2"] = self.generate_http2_logs(identity, scenario)
        return results


def main():
    scenarios = ["success", "auth_failed", "sub_not_found", "smf_timeout", "ims_forbidden"]
    all_results = {}
    for scenario in scenarios:
        gen = LogGenerator()
        results = gen.generate_all(scenario=scenario)
        all_results[scenario] = results

    print("\n" + "=" * 60)
    print("[loggen] All log files generated successfully:")
    print("=" * 60)
    for scenario, files in all_results.items():
        print(f"\n  Scenario: {scenario}")
        for log_type, path in files.items():
            print(f"    {log_type:8s} -> {path}")
    print("\n[loggen] Done.")


if __name__ == "__main__":
    main()
