import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db

class Equipo(db.Model):
    __tablename__ = 'equipos'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # FK a la tabla Sites
    site_id = db.Column(UUID(as_uuid=True), db.ForeignKey('sites.id'), nullable=False)
    
    nombre = db.Column(db.String(100), nullable=False)
    serial = db.Column(db.String(100), nullable=False, unique=True)
    ha_habilitado = db.Column(db.Boolean, default=False)
    segundo_serial = db.Column(db.String(100), nullable=True)
    hostname = db.Column(db.String(100), nullable=True)
    fecha_alta = db.Column(db.DateTime, default=db.func.now())
    
    # Store parsed config info (Interfaces, System, etc.)
    config_data = db.Column(JSONB)
    
    # Store full raw config file content (for Raw Config tab)
    raw_config = db.Column(db.Text)

    # Relación con Políticas - cascade delete
    politicas = db.relationship('Policy', backref='equipo', lazy=True, cascade="all, delete-orphan")
    
    # Relación con PolicyHistory - cascade delete
    policy_history = db.relationship('PolicyHistory', backref='device', lazy=True, cascade="all, delete-orphan")
    
    # Relación con ConfigHistory - cascade delete
    config_history = db.relationship('ConfigHistory', backref='device', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Equipo {self.nombre}>"