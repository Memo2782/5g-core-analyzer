from scapy.all import IP, TCP, wrpcap
import os

def crear_pcap_prueba():
    print("[+] Fabricando archivo PCAP de prueba para 5G Core...")
    paquetes = []
    
    # Asegurar que la carpeta data_samples exista
    os.makedirs("data_samples", exist_ok=True)
    
    # Simular Paquete 1: Tráfico normal AMF (10.0.0.1) a UDM (10.0.0.2)
    p1 = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5001, dport=80)/"HTTP/2 200 OK"
    paquetes.append(p1)
    
    # Simular Paquete 2: Error 404 (Usuario no encontrado en UDM)
    p2 = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5002, dport=80)/"HTTP/2 404 Not Found"
    paquetes.append(p2)
    
    # Simular Paquete 3: Error 504 (Gateway Timeout entre AMF y SMF 10.0.0.3)
    p3 = IP(src="10.0.0.1", dst="10.0.0.3")/TCP(sport=5003, dport=80)/"HTTP/2 504 Gateway Timeout"
    paquetes.append(p3)
    
    # Guardar el archivo en la carpeta de muestras
    ruta_salida = os.path.join("data_samples", "sample_trace.pcap")
    wrpcap(ruta_salida, paquetes)
    print(f"[✅] Archivo creado exitosamente en: {ruta_salida}")

if __name__ == "__main__":
    crear_pcap_prueba()
