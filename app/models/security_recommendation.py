from datetime import datetime
import uuid
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db

class SecurityRecommendation(db.Model):
    """
    Stores security recommendations generated from log analysis
    """
    __tablename__ = 'security_recommendations'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey('equipos.id'))
    
    # Recommendation Info
    category = db.Column(db.String(50))  # policy, traffic, security, optimization
    severity = db.Column(db.String(20))  # critical, high, medium, low, info
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    
    # Related Policy (if applicable)
    related_policy_id = db.Column(db.Integer)
    related_vdom = db.Column(db.String(50))
    
    # Remediation (v1.3.1)
    cli_remediation = db.Column(db.Text)
    suggested_policy = db.Column(JSONB)  # Structured data for new policy: {src, dst, service, action}
    
    # Evidence
    evidence = db.Column(JSONB)  # Log samples, stats, etc.
    affected_count = db.Column(db.Integer)  # Number of logs/policies affected
    
    # Status
    status = db.Column(db.String(20), default='open')  # open, acknowledged, resolved, ignored
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.String(100))
    
    device = db.relationship('Equipo', backref='security_recommendations')
