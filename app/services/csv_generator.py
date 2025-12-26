import csv
import io
from datetime import datetime

class CsvReportGenerator:
    def __init__(self, buffer):
        self.buffer = buffer

    def _format_value(self, value):
        """Limpia listas o valores vacíos para el CSV"""
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        if value is None:
            return ""
        return str(value)

    def generate(self, device, policies, report_type):
        # Usamos StringIO para escribir texto (CSV), luego encode a bytes si es necesario
        # Pero report_routes usa BytesIO. Flask send_file/Response puede manejar ambos si se configuran bien.
        # wrapper de texto sobre el buffer binario
        text_buffer = io.TextIOWrapper(self.buffer, encoding='utf-8', newline='')
        
        writer = csv.writer(text_buffer)
        
        # 1. Metadata del Reporte (Header custom)
        writer.writerow(["REPORTE DE SEGURIDAD - ISSEC"])
        writer.writerow(["Fecha", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["Dispositivo", device.nombre])
        writer.writerow(["Serial", device.serial])
        vdoms = sorted(list(set(p.vdom for p in policies if p.vdom)))
        vdom_str = ", ".join(vdoms) if vdoms else "N/A"
        writer.writerow(["VDOM (Contexto)", vdom_str])
        writer.writerow(["Tipo Reporte", report_type])
        writer.writerow([]) # Espacio vacío

        # 2. Definición de Columnas (Mismas que PDF para consistencia)
        columns_map = [
            ("ID", "ID"),
            ("VDOM", "VDOM"),
            ("Name", "Name"),
            ("From", "From"),
            ("Users", "Users"),
            ("Groups", "Groups"),
            ("Source", "Source"),
            ("Src Addr", "Source Address"),
            ("To", "To"),
            ("Dest", "Destination"),
            ("Dst Addr", "Destination Address"),
            ("Service", "Service"),
            ("Action", "Action"),
            ("NAT", "NAT"),
            ("IP Pool", "IP Pool"),
            ("Seq Group", "Sequence Grouping"),
            ("Bytes", "Bytes"),
            ("Hits", "Hit Count"),
            ("Comments", "Comments"),
            ("Status", "Status")
        ]
        
        # Escribir Cabecera de Tabla
        writer.writerow([col[0] for col in columns_map])
        
        # 3. Datos
        for p in policies:
            row = []
            json_data = p.raw_data if p.raw_data else {}
            
            for col_name, json_key in columns_map:
                if json_key == "Name":
                    val = json_data.get("Name") or json_data.get("Policy", "")
                elif json_key == "VDOM":
                    val = p.vdom
                else:
                    val = json_data.get(json_key, "")
                
                row.append(self._format_value(val))
            
            writer.writerow(row)
            
        # Flush para asegurar que todo se escribe en el buffer subyacente
        text_buffer.flush()
        # Importante: detach() para separar el wrapper del buffer subyacente y NO cerrarlo
        text_buffer.detach()
