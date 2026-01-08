"""
VDOM History Model - Track VDOM configuration changes
IS Security Toolset 1.3.0
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db


class VDOMHistory(db.Model):
    """Track VDOM configuration changes over time"""
    __tablename__ = 'vdom_history'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vdom_id = Column(UUID(as_uuid=True), index=True, nullable=False)  # Not FK to allow deleted VDOMs
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False)
    
    change_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    change_type = Column(String(20), nullable=False)  # create, modify, delete
    
    # What changed
    delta = Column(JSONB)  # {field: {old: x, new: y}}
    
    # Full VDOM config at this point
    snapshot = Column(JSONB)
    
    def __repr__(self):
        return f"<VDOMHistory {self.vdom_id} - {self.change_type}>"
