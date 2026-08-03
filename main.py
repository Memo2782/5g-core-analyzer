import os
from core.log_processor import CoreLogProcessor
from reports.excel_generator import CoreExcelGenerator

def ejecutar_auditoria_completa_5g():
    print("\n" + "="*70)
    print(" 📶 3GPP END-TO-END MULTI-NODE NETWORK AUDITOR (5GC)")
    print("="*70)
    
    procesador = CoreLogProcessor()
    generador_excel = CoreExcelGenerator()

    # Chronological dataset matching your exact local JSON keys string-for-string
    trazas_multi_nodo = [
        # Phase 1: 5G SA Registration Anomalies
        {"timestamp": "2026-07-28T14:00:01Z", "source_nf": "AMF_Node_01", "dest_nf": "AUSF_Server_L1", "interface": "N12", "http_status": "401", "details": "Registration Request - Auth Handshake Match"},
        {"timestamp": "2026-07-28T14:00:03Z", "source_nf": "AMF_Node_01", "dest_nf": "UDM_Central", "interface": "N8", "http_status": "404", "details": "Subscription Data Fetch Profile Query"},
        
        # Phase 2: 5G PDU Data Session Tracking
        {"timestamp": "2026-07-28T14:05:22Z", "source_nf": "AMF_Node_01", "dest_nf": "SMF_Cloud_02", "interface": "N11", "http_status": "504", "details": "Create SM Context Timed Out"},
        
        # Phase 3: Legacy Core Elements Interoperability 
        {"timestamp": "2026-07-28T14:10:00Z", "source_nf": "MME_LTE_04", "dest_nf": "HSS_Legacy", "interface": "S6a", "http_status": "5001", "details": "Diameter User Unknown Query Profile"},
        {"timestamp": "2026-07-28T14:11:15Z", "source_nf": "MSC_Old_Node", "dest_nf": "HLR_Central", "interface": "SS7/MAP", "http_status": "13", "details": "MAP Update Location Regional Restriction"}
    ]

    alertas_detectadas = []
    print(f"[+] Procesando {len(trazas_multi_nodo)} eventos correlacionados entre nodos...\n")

    for log in trazas_multi_nodo:
        resultado = procesador.analizar_evento(log)
        if resultado:
            alertas_detectadas.append(resultado)
            print(f"[{resultado['timestamp']}] 🚨 ANOMALÍA DETECTADA en Interfaz {resultado['interfaz']}")
            print(f"    🔸 Dominio: {resultado['procedimiento']}")
            print(f"    🔸 Flujo de Nodos: {resultado['origen']} ➡️ {resultado['destino']}")
            print(f"    🔸 Protocolo/Código: {resultado['codigo']} -> {resultado['error_3gpp']}")
            print(f"    🔸 Descripción: {resultado['causa_raiz']}")
            print(f"    🔸 Solución L3: {resultado['solucion']}")
            print("-" * 70)

    # Export dataset to the Premium Excel file layout
    if alertas_detectadas:
        generador_excel.generar_reporte(alertas_detectadas)
        print(f"\n[✅] Auditoría E2E Finalizada. Se exportaron {len(alertas_detectadas)} fallas al reporte Excel.")
    else:
        print("[-] No se pudieron emparejar las alertas. Revisa los códigos del catálogo JSON.")
    
    print("="*70 + "\n")

if __name__ == "__main__":
    ejecutar_auditoria_completa_5g()
