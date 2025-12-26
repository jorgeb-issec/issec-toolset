"""
SavedReport Model - Stores custom report templates
"""
from app.extensions.db import db
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from datetime import datetime
import uuid

class SavedReport(db.Model):
    __tablename__ = 'saved_reports'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    report_type = Column(String(50), default='custom')  # 'policy', 'device', 'custom'
    
    # Saved filter criteria as JSON
    filters = Column(JSONB, default={})
    
    # Ownership
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'))
    company_id = Column(UUID(as_uuid=True), ForeignKey('companies.id'))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = db.relationship('User', backref='saved_reports')
    company = db.relationship('Company', backref='saved_reports')
    
    def __repr__(self):
        return f"<SavedReport {self.name}>"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'description': self.description,
            'report_type': self.report_type,
            'filters': self.filters,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
