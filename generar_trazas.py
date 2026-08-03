from scapy.all import IP, TCP, wrpcap
import os

SUBSCRIBERS = [
    {"imsi": "001010000000001", "msisdn": "1555010001", "call_id": "10001@ims.core.net"},
    {"imsi": "001010000000002", "msisdn": "1555010002", "call_id": "10002@ims.core.net"},
    {"imsi": "001010000000003", "msisdn": "1555010003", "call_id": "10003@ims.core.net"},
    {"imsi": "001010000000004", "msisdn": "1555010004", "call_id": "10004@ims.core.net"},
    {"imsi": "001010000000005", "msisdn": "1555010005", "call_id": "10005@ims.core.net"},
]


def _build_ims_forbidden_packets(sub):
    """Build packets simulating an IMS call forbidden error for a specific subscriber."""
    packets = []
    imsi = sub["imsi"]
    msisdn = sub["msisdn"]
    call_id = sub["call_id"]

    # 1. UE -> PCSCF: SIP INVITE with IMSI/MSISDN/Call-ID
    p = IP(src="10.100.9.99", dst="10.200.1.1")/TCP(sport=5060, dport=5060)/f"SIP INVITE sip:called@pcscf.ims; IMSI={imsi} MSISDN={msisdn} Call-ID={call_id}"
    packets.append(p)

    # 2. PCSCF -> SCSCF: SIP INVITE forwarded
    p = IP(src="10.200.1.1", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={call_id} | iFC_Routing"
    packets.append(p)

    # 3. SCSCF -> TAS: SIP INVITE triggered
    p = IP(src="10.200.1.2", dst="10.200.8.8")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={call_id} | TAS_Trigger"
    packets.append(p)

    # 4. TAS -> SCSCF: 403 Forbidden (voice not provisioned)
    p = IP(src="10.200.8.8", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP 403 Forbidden | IMSI={imsi} MSISDN={msisdn} Call-ID={call_id} | User Not Provisioned in TAS DB"
    packets.append(p)

    return packets


def _build_5g_registration_failure_packets(sub):
    """Build packets simulating 5G registration + PDU session failure for a specific subscriber."""
    packets = []
    imsi = sub["imsi"]
    msisdn = sub["msisdn"]

    # 1. UE -> gNB: NAS Registration Request
    p = IP(src="10.100.9.99", dst="10.100.1.5")/TCP(sport=8080, dport=80)/f"NAS Registration Request | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 2. gNB -> AMF: N2 Registration
    p = IP(src="10.100.1.5", dst="10.100.1.10")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | N2 Initial Registration | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 3. AMF -> AUSF: Authentication Request (OK)
    p = IP(src="10.100.1.10", dst="10.100.1.20")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | Nausf_UEAuthentication | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 4. AMF -> UDM: Subscription Data Request (404 - subscriber not found)
    p = IP(src="10.100.1.10", dst="10.100.1.30")/TCP(sport=8080, dport=80)/f"HTTP/2 404 Not Found | Nudm_SDM_Get | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 5. AMF -> SMF: Create SM Context (504 - timeout)
    p = IP(src="10.100.1.10", dst="10.100.5.11")/TCP(sport=8082, dport=80)/f"HTTP/2 504 Gateway Timeout | Nsmf_PDUSession | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 6. UE -> PCSCF: SIP INVITE for VoNR (fails)
    p = IP(src="10.100.9.99", dst="10.200.1.1")/TCP(sport=5060, dport=5060)/f"SIP INVITE sip:called@pcscf.ims; IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']}"
    packets.append(p)

    # 7. PCSCF -> SCSCF
    p = IP(src="10.200.1.1", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | iFC_Routing"
    packets.append(p)

    # 8. SCSCF -> TAS
    p = IP(src="10.200.1.2", dst="10.200.8.8")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | TAS_Trigger"
    packets.append(p)

    # 9. TAS -> SCSCF: 403 Forbidden
    p = IP(src="10.200.8.8", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP 403 Forbidden | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | User Not Provisioned"
    packets.append(p)

    return packets


def _build_successful_call_packets(sub):
    """Build packets simulating a successful registration + VoNR call."""
    packets = []
    imsi = sub["imsi"]
    msisdn = sub["msisdn"]

    # 1. UE -> gNB: NAS Registration Request
    p = IP(src="10.100.9.99", dst="10.100.1.5")/TCP(sport=8080, dport=80)/f"NAS Registration Request | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 2. gNB -> AMF
    p = IP(src="10.100.1.5", dst="10.100.1.10")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | N2 Initial Registration | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 3. AMF -> AUSF: 200 OK
    p = IP(src="10.100.1.10", dst="10.100.1.20")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | Nausf_UEAuthentication | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 4. AMF -> UDM: 200 OK
    p = IP(src="10.100.1.10", dst="10.100.1.30")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | Nudm_SDM_Get | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 5. AMF -> SMF: 201 Created
    p = IP(src="10.100.1.10", dst="10.100.5.11")/TCP(sport=8082, dport=80)/f"HTTP/2 201 Created | Nsmf_PDUSession | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    # 6. UE -> PCSCF: SIP INVITE
    p = IP(src="10.100.9.99", dst="10.200.1.1")/TCP(sport=5060, dport=5060)/f"SIP INVITE sip:called@pcscf.ims; IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']}"
    packets.append(p)

    # 7. PCSCF -> SCSCF
    p = IP(src="10.200.1.1", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | iFC_Routing"
    packets.append(p)

    # 8. SCSCF -> TAS
    p = IP(src="10.200.1.2", dst="10.200.8.8")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | TAS_Trigger"
    packets.append(p)

    # 9. TAS -> SCSCF: 200 OK
    p = IP(src="10.200.8.8", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP 200 OK | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | Call Completed"
    packets.append(p)

    return packets


def _build_smf_timeout_packets(sub):
    """Build packets simulating 5G SMF timeout (504) + IMS 403."""
    packets = []
    imsi = sub["imsi"]
    msisdn = sub["msisdn"]

    p = IP(src="10.100.1.10", dst="10.100.1.20")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | Nausf_UEAuthentication | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.1.10", dst="10.100.1.30")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | Nudm_SDM_Get | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.1.10", dst="10.100.5.11")/TCP(sport=8082, dport=80)/f"HTTP/2 504 Gateway Timeout | Nsmf_PDUSession | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.9.99", dst="10.200.1.1")/TCP(sport=5060, dport=5060)/f"SIP INVITE sip:called@pcscf.ims; IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']}"
    packets.append(p)

    p = IP(src="10.200.1.1", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | iFC_Routing"
    packets.append(p)

    p = IP(src="10.200.1.2", dst="10.200.8.8")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | TAS_Trigger"
    packets.append(p)

    p = IP(src="10.200.8.8", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP 403 Forbidden | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | User Not Provisioned"
    packets.append(p)

    p = IP(src="10.100.5.11", dst="10.100.1.10")/TCP(sport=8082, dport=80)/f"HTTP/2 504 Gateway Timeout | Nsmf_PDUSession Response | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    return packets


def _build_auth_failure_packets(sub):
    """Build packets simulating 5G authentication failure (401) + IMS 403."""
    packets = []
    imsi = sub["imsi"]
    msisdn = sub["msisdn"]

    p = IP(src="10.100.9.99", dst="10.100.1.5")/TCP(sport=8080, dport=80)/f"NAS Registration Request | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.1.5", dst="10.100.1.10")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | N2 Initial Registration | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.1.10", dst="10.100.1.20")/TCP(sport=8080, dport=80)/f"HTTP/2 401 Unauthorized | Nausf_UEAuthentication | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.1.10", dst="10.100.1.30")/TCP(sport=8080, dport=80)/f"HTTP/2 200 OK | Nudm_SDM_Get | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.1.10", dst="10.100.5.11")/TCP(sport=8082, dport=80)/f"HTTP/2 201 Created | Nsmf_PDUSession | IMSI={imsi} MSISDN={msisdn}"
    packets.append(p)

    p = IP(src="10.100.9.99", dst="10.200.1.1")/TCP(sport=5060, dport=5060)/f"SIP INVITE sip:called@pcscf.ims; IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']}"
    packets.append(p)

    p = IP(src="10.200.1.1", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | iFC_Routing"
    packets.append(p)

    p = IP(src="10.200.1.2", dst="10.200.8.8")/TCP(sport=5060, dport=5060)/f"SIP INVITE | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | TAS_Trigger"
    packets.append(p)

    p = IP(src="10.200.8.8", dst="10.200.1.2")/TCP(sport=5060, dport=5060)/f"SIP 403 Forbidden | IMSI={imsi} MSISDN={msisdn} Call-ID={sub['call_id']} | User Not Provisioned"
    packets.append(p)

    return packets


def fabricar_capturas_totales_5g_ims():
    print("\n" + "=" * 60)
    print("[+] INICIANDO EMULADOR DE SEÑALIZACIÓN CARRIER-CLASS (5GC + IMS)")
    print("=" * 60)

    os.makedirs("data_samples", exist_ok=True)

    for sub in SUBSCRIBERS:
        imsi = sub["imsi"]
        msisdn = sub["msisdn"]

        # Each subscriber gets a DISTINCT error profile:
        # 1: IMS 403 only (4 packets)
        # 2: 5G 404 + 504 + IMS 403 (registration + SMF timeout profile)
        # 3: Success (all 200)
        # 4: 5G 504 only + IMS 403 (SMF timeout profile - no 404)
        # 5: 5G 401 only + IMS 403 (auth failure profile)

        if int(sub["imsi"]) % 5 == 1:
            packets = _build_ims_forbidden_packets(sub)
        elif int(sub["imsi"]) % 5 == 2:
            packets = _build_5g_registration_failure_packets(sub)
        elif int(sub["imsi"]) % 5 == 3:
            packets = _build_successful_call_packets(sub)
        elif int(sub["imsi"]) % 5 == 4:
            packets = _build_smf_timeout_packets(sub)
        else:
            packets = _build_auth_failure_packets(sub)

        ruta_salida = os.path.join("data_samples", f"trace_{imsi}_{msisdn}.pcap")
        wrpcap(ruta_salida, packets)
        print(f"[✅] Traza generada: {ruta_salida} (IMSI={imsi}, MSISDN={msisdn}, {len(packets)} packets)")

    print("=" * 60)
    print(f"[+] {len(SUBSCRIBERS)} call flows generated with different IMSI/MSISDN identities")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    fabricar_capturas_totales_5g_ims()
