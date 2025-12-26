import json
from app.models.policy import Policy
from app.extensions.db import db

import re

def parse_hit_count(val):
    if not val: return 0
    if isinstance(val, int): return val
    # Strip everything that is not a digit
    # Handles "44.728.514" -> "44728514"
    # Handles "1,000" -> "1000"
    cleaned = re.sub(r'[^\d]', '', str(val))
    try:
        return int(cleaned)
    except:
        return 0

def parse_bytes_str(size_str):
    if not size_str: return 0
    if isinstance(size_str, (int, float)): return int(size_str)
    
    units = {
        "B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4, "PB": 1024**5
    }
    
    # Handle "64.5 MB" or "1024"
    s = str(size_str).strip()
    parts = s.split()
    
    try:
        val_str = parts[0]
        # Remove thousands separators (dots or commas) BUT we need to be careful about decimal point
        # "1.5 MB" -> 1.5 (Decimal)
        # "1,500 MB" -> 1500
        # "44.728.514" (Bytes) -> Integer?
        
        # Strategy: If it has units, it usually follows standard "1.5 GB" (dot is decimal).
        # If it is raw bytes "44728514", it has no unit.
        
        if len(parts) >= 2:
            # Has unit -> Dot is likely decimal
            val = float(val_str.replace(',', '')) # US Style standard for logs usually
            unit = parts[1].upper()
            return int(val * units.get(unit, 1))
        else:
            # Raw number (e.g. "44.728.514" or "44,728,514")
            # Assume formatted integer
            cleaned = re.sub(r'[^\d]', '', val_str)
            return int(cleaned)
    except:
        return 0

def list_to_str(val):
    """Convierte listas JSON a string separado por comas"""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    return str(val) if val else ""

def get_nat_status(r):
    val = r.get('NAT', '')
    if val == 1 or val is True or str(val).lower() in ['enabled', 'enable', 'snat', 'dnat','nat']:
        return 'Enabled'
    return 'Disabled'

def process_policy_json(file_stream, device_id, vdom, session):
    try:
        content = json.load(file_stream)
        data_list = content if isinstance(content, list) else [content]
        
        count = 0
        for r in data_list:
            b_raw = r.get('Bytes', '0 B')
            b_int = parse_bytes_str(b_raw)
            hits = parse_hit_count(r.get('Hit Count', 0))
            
            # --- 1. EXTRACCIÓN INTELIGENTE ---
            src_list = r.get('From') or r.get('srcintf') or []
            dst_list = r.get('To') or r.get('dstintf') or []
            
            # Caso especial: "Interface Pair"
            # Si las listas están vacías, intentamos parsear el par
            if not src_list and not dst_list:
                pair = r.get('Interface Pair', '')
                if pair and ',' in pair:
                    parts = pair.split(',')
                    if len(parts) >= 2:
                        # Limpiamos espacios
                        s_val = parts[0].strip()
                        d_val = parts[1].strip()                        
                        src_list = [s_val]
                        dst_list = [d_val]
                        # --- 2. ENRIQUECIMIENTO DEL JSON (MODIFICACIÓN CLAVE) ---
                        # Aquí "corregimos" el JSON antes de guardarlo. 
                        # Agregamos 'From' y 'To' explícitamente para que se vean en el Modal.
                        r['From'] = src_list
                        r['To'] = dst_list

            # Convertimos a string para las columnas de búsqueda SQL
            src_str = list_to_str(src_list)
            dst_str = list_to_str(dst_list)

            # Nombre
            nombre_pol = r.get('Name', '') or r.get('Policy', '')

            new_pol = Policy(
                device_id=device_id,
                vdom=vdom,
                policy_id=str(r.get('ID', '0')),
                
                # Columnas SQL (para la tabla y filtros)
                src_intf=src_str,
                dst_intf=dst_str,
                
                src_addr=list_to_str(r.get('Source Address', r.get('Source', []))),
                dst_addr=list_to_str(r.get('Destination Address', r.get('Destination', []))),
                service=list_to_str(r.get('Service', [])),
                action=r.get('Action', 'DENY'),
                nat=get_nat_status(r),
                
                name=str(nombre_pol)[:250],
                bytes_int=b_int,
                hit_count=hits,
                
                # JSONB (Datos completos + Enriquecidos)
                raw_data=r 
            )
            session.add(new_pol)
            count += 1
            
        session.commit()
        return True, f"{count} políticas importadas correctamente."
    except Exception as e:
        session.rollback()
        return False, f"Error procesando JSON: {str(e)}"