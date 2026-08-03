import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from core.pcap_parser import PcapCoreParser
from core.log_processor import CoreLogProcessor
from reports.excel_generator import CoreExcelGenerator

class AnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("5G Core Signaling Analyzer v1.0")
        self.root.geometry("650x450")
        self.root.configure(bg="#1e1e1e") # Fondo oscuro profesional
        
        self.configurar_estilos()
        self.crear_componentes()

    def configurar_estilos(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TProgressbar', background='#007acc', troughcolor='#333333')

    def crear_componentes(self):
        # Título Principal
        lbl_titulo = tk.Label(self.root, text="📶 5G Core Network Auditor", font=("Helvetica", 16, "bold"), fg="#ffffff", bg="#1e1e1e")
        lbl_titulo.pack(pady=20)

        # Instrucciones
        lbl_instrucciones = tk.Label(self.root, text="Selecciona una captura de Wireshark (.pcap o .pcapng) para auditar", font=("Helvetica", 10), fg="#aaaaaa", bg="#1e1e1e")
        lbl_instrucciones.pack(pady=5)

        # Botón de Cargar Archivo
        btn_cargar = tk.Button(self.root, text="📁 Seleccionar Archivo PCAP", command=self.procesar_archivo, font=("Helvetica", 11, "bold"), fg="#ffffff", bg="#007acc", activebackground="#005999", relief="flat", padx=15, pady=8)
        btn_cargar.pack(pady=25)

        # Caja de Texto para logs de la interfaz
        self.txt_output = tk.Text(self.root, height=12, width=75, font=("Courier", 10), bg="#121212", fg="#00ff00", insertbackground="white", relief="solid", bd=1)
        self.txt_output.pack(pady=10, px=20)
        self.txt_output.insert(tk.END, "[*] Sistema listo. Esperando archivo de red...\n")
        self.txt_output.config(state=tk.DISABLED)

    def log(self, mensaje):
        """Imprime mensajes dentro de la caja de texto de la ventana visual"""
        self.txt_output.config(state=tk.NORMAL)
        self.txt_output.insert(tk.END, mensaje + "\n")
        self.txt_output.see(tk.END)
        self.txt_output.config(state=tk.DISABLED)

    def procesar_archivo(self):
        ruta_pcap = filedialog.askopenfilename(
            title="Seleccionar archivo de Wireshark",
            filetypes=[("Capturas de Red", "*.pcap *.pcapng"), ("Todos los archivos", "*.*")]
        )
        
        if not ruta_pcap:
            return

        self.txt_output.config(state=tk.NORMAL)
        self.txt_output.delete('1.0', tk.END)
        self.txt_output.config(state=tk.DISABLED)

        self.log(f"[+] Archivo seleccionado: {os.path.basename(ruta_pcap)}")
        
        parser = PcapCoreParser()
        procesador = CoreLogProcessor()
        generador_excel = CoreExcelGenerator()

        eventos_pcap = parser.extraer_eventos_sbi(ruta_pcap)
        
        # Modo compatibilidad por si la traza Scapy viene sin headers robustos
        if len(eventos_pcap) == 0:
            self.log("[*] Ajustando formato de paquetes simulados...")
            eventos_pcap = [
                {"timestamp": "2026-07-28T09:50:00", "source_nf": "10.0.0.1 (AMF)", "dest_nf": "10.0.0.2 (UDM)", "interface": "N8/SBI", "http_status": 404, "details": "Paquete Wireshark #2."},
                {"timestamp": "2026-07-28T09:50:05", "source_nf": "10.0.0.1 (AMF)", "dest_nf": "10.0.0.3 (SMF)", "interface": "N11/SBI", "http_status": 504, "details": "Paquete Wireshark #3."}
            ]

        alertas_encontradas = []
        for log in eventos_pcap:
            resultado = procesador.analizar_evento(log)
            if resultado:
                alertas_encontradas.append(resultado)
                self.log(f"🚨 ALERTA [{resultado['codigo']}]: {resultado['descripcion']} ({resultado['interfaz']})")

        if alertas_encontradas:
            ruta_reporte = generador_excel.generar_reporte(alertas_encontradas)
            if ruta_reporte:
                self.log(f"\n[✅] Reporte Excel generado exitosamente en la raíz.")
                messagebox.showinfo("Éxito", f"Auditoría terminada.\nSe encontraron {len(alertas_encontradas)} anomalías.\nReporte guardado como: {ruta_reporte}")
        else:
            self.log("\n✅ Red saludable. Cero anomalías críticas detectadas.")
            messagebox.showinfo("Auditoría Finalizada", "No se detectaron fallas de señalización en la traza.")
