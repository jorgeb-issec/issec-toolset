import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db

class Site(db.Model):
    __tablename__ = 'sites'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nombre = db.Column(db.String(100), nullable=False, unique=True)
    direccion = db.Column(db.String(200), nullable=True)
    
    
    # Relationship removed: Site and Equipo are in DIFFERENT databases (Main vs Tenant).
    # Linkage is logical via site_id UUID only.

    
    # Store topology layout/config
    topology_data = db.Column(JSONB, nullable=True)

    def __repr__(self):
        return f"<Site {self.nombre}>"