import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db

class Policy(db.Model):
    __tablename__ = 'policies'

    # --- Identificadores de DB ---
    uuid = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey('equipos.id'), nullable=False)
    
    # --- Datos Meta ---
    vdom = db.Column(db.String(50), nullable=False, default="root")
    policy_id = db.Column(db.String(50), index=True) 
    
    # --- Columnas Indexadas (NECESARIAS para los filtros .ilike y ordenamiento) ---
    name = db.Column(db.String(255), index=True) 
    
    src_intf = db.Column(db.String(500), index=True)
    dst_intf = db.Column(db.String(500), index=True)
    
    src_addr = db.Column(db.Text) # Text para soportar listas largas convertidas a string
    dst_addr = db.Column(db.Text)
    service = db.Column(db.Text)
    
    action = db.Column(db.String(50), index=True)
    nat = db.Column(db.String(50))
    
    # --- Datos Numéricos (BigInteger para soportar TBs de tráfico) ---
    bytes_int = db.Column(db.BigInteger, default=0, index=True)
    hit_count = db.Column(db.BigInteger, default=0)
    
    # --- EL JSON COMPLETO ---
    raw_data = db.Column(JSONB)

    # --- Propiedades Virtuales (Para visualización) ---
    @property
    def bytes_raw(self):
        """
        Extrae el string original de bytes (ej: '67.93 TB') desde el JSON.
        Si no existe, devuelve '0 B'.
        """
        if self.raw_data:
            return self.raw_data.get('Bytes', '0 B')
        return '0 B'

    def __repr__(self):
        return f"<Policy {self.policy_id}>"