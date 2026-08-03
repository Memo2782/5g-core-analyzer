from scapy.all import IP, TCP, wrpcap
import os

def fabricar_capturas_operadora():
    print("[+] Fabricando lote de trazas complejas multicapa...")
    os.makedirs("data_samples", exist_ok=True)
    
    # -------------------------------------------------------------------------
    # CAPTURA 1: traza_amf_access.pcap
    # Simula la interfaz de acceso. El tráfico inicial se procesa bien (200 OK)
    # pero falla estrepitosamente cuando intenta consultar al repositorio central (404)
    # -------------------------------------------------------------------------
    paquetes_amf = []
    
    # Paquete 1: Handshake de movilidad inicial AMF -> AUSF (Exitoso)
    p_amf_1 = IP(src="10.100.1.10", dst="10.100.1.20")/TCP(sport=8080, dport=80)/"HTTP/2 200 OK"
    paquetes_amf.append(p_amf_1)
    
    # Paquete 2: Petición de perfil de abonado AMF -> UDM (Falla de aprovisionamiento)
    p_amf_2 = IP(src="10.100.1.10", dst="10.100.1.30")/TCP(sport=8081, dport=80)/"HTTP/2 404 Not Found"
    paquetes_amf.append(p_amf_2)
    
    ruta_amf = os.path.join("data_samples", "traza_amf_access.pcap")
    wrpcap(ruta_amf, paquetes_amf)
    print(f"[✅] Traza de Acceso AMF guardada en: {ruta_amf}")

    # -------------------------------------------------------------------------
    # CAPTURA 2: traza_smf_session.pcap
    # Simula el plano de sesión de datos corporativo. Sufre un timeout en cascada
    # debido a la falta de respuesta del control plane de políticas.
    # -------------------------------------------------------------------------
    paquetes_smf = []
    
    # Paquete 1: Intento de registro de sesión SMF -> PCF (Vence el temporizador de guardia)
    p_smf_1 = IP(src="10.200.5.11", dst="10.200.5.50")/TCP(sport=9000, dport=80)/"HTTP/2 504 Gateway Timeout"
    paquetes_smf.append(p_smf_1)
    
    ruta_smf = os.path.join("data_samples", "traza_smf_session.pcap")
    wrpcap(ruta_smf, paquetes_smf)
    print(f"[✅] Traza de Sesión SMF guardada en: {ruta_smf}")

if __name__ == "__main__":
    fabricar_capturas_operadora()
