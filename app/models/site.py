import uuid
from sqlalchemy.dialects.postgresql import UUID
from app.extensions.db import db

class Site(db.Model):
    __tablename__ = 'sites'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nombre = db.Column(db.String(100), nullable=False, unique=True)
    direccion = db.Column(db.String(200), nullable=True)
    
    # Relación: Un Sitio tiene muchos Equipos
    equipos = db.relationship('Equipo', backref='site', lazy=True)

    def __repr__(self):
        return f"<Site {self.nombre}>"