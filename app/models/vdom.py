import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db
from datetime import datetime

class VDOM(db.Model):
    __tablename__ = 'vdoms'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # FK to Equipment
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey('equipos.id'), nullable=False)
    
    name = db.Column(db.String(100), nullable=False)
    comments = db.Column(db.String(255), nullable=True)
    
    config_data = db.Column(JSONB)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    equipo = db.relationship('Equipo', backref=db.backref('vdoms', lazy=True, cascade="all, delete-orphan"))

    def __repr__(self):
        return f"<VDOM {self.name} on {self.device_id}>"
