import json
import os

class CoreLogProcessor:
    def __init__(self):
        ruta_config = os.path.join('config', '3gpp_codes.json')
        with open(ruta_config, 'r', encoding='utf-8') as f:
            self.catalogo_3gpp = json.load(f)

    def analizar_evento(self, log_dict):
        """Universal parser that reads flat strings and nested objects without breaking"""
        http_status = str(log_dict.get('http_status', '')).strip()
        origen = log_dict.get('source_nf', '').upper()
        destino = log_dict.get('dest_nf', '').upper()
        interfaz = log_dict.get('interface', '').upper()
        details = log_dict.get('details', 'Captura de traza analizada.')

        if not http_status:
            return None

        # Loop through every category dynamically
        for cat_name, diccionario_cat in self.catalogo_3gpp.items():
            if isinstance(diccionario_cat, dict) and http_status in diccionario_cat:
                falla = diccionario_cat[http_status]
                
                # Context domain tagging
                contexto_proc = "5GS_SIGNALING"
                if any(x in cat_name.lower() for x in ["legacy", "4g", "3g", "2g", "map", "diameter"]):
                    contexto_proc = "LEGACY_INTEROPERABILITY"

                # Check if it's a deep nested dictionary or a flat string description
                if isinstance(falla, dict):
                    error_name = falla.get('name', falla.get('significado', 'Protocol Error'))
                    causa = falla.get('desc', falla.get('causa', falla.get('causa_raiz', 'Deep trace required.')))
                    solucion = falla.get('ts', falla.get('solucion', falla.get('solucion_L3', 'Verify vendor config.')))
                else:
                    # Handle flat string format seamlessly
                    error_name = "3GPP Core Error Flag"
                    causa = str(falla)
                    solucion = "Review corresponding 3GPP Technical Specification guidelines for troubleshooting."

                return {
                    "timestamp": log_dict.get('timestamp', 'Desconocido'),
                    "procedimiento": contexto_proc,
                    "origen": origen,
                    "destino": destino,
                    "interfaz": interfaz,
                    "codigo": http_status,
                    "error_3gpp": error_name,
                    "causa_raiz": causa,
                    "solucion": solucion,
                     "evidencia": details
                 }

        # Fallback: if no catalog match, still return a generic alert for non-2xx codes
        if http_status and http_status not in ("200", "201", "204"):
            return {
                "timestamp": log_dict.get('timestamp', 'Desconocido'),
                "procedimiento": log_dict.get('procedimiento', interfaz if interfaz else 'SIGNALING'),
                "origen": origen,
                "destino": destino,
                "interfaz": interfaz,
                "codigo": http_status,
                "error_3gpp": "Protocol Error (No match in 3GPP catalog)",
                "causa_raiz": "Falla detectada en traza de señalización sin catálogo 3GPP específico. Revisar payload completo.",
                "solucion": "Verificar logs internos de la NF y validar configuración de interfaz.",
                "evidencia": details
            }
        return None
