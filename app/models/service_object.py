"""
Service Objects Model - FortiGate firewall service definitions
IS Security Toolset 1.3.0
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db


class ServiceObject(db.Model):
    """
    Represents a FortiGate service object used in policies.
    Can be custom services or groups.
    """
    __tablename__ = 'service_objects'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False, index=True)
    vdom_id = Column(UUID(as_uuid=True), ForeignKey('vdoms.id'), nullable=True, index=True)
    
    # Service identification
    name = Column(String(255), nullable=False, index=True)
    category = Column(String(100))  # Web Access, Remote Access, Email, File Access, etc.
    protocol = Column(String(50))  # TCP/UDP/SCTP, ICMP, IP, ALL
    
    # For TCP/UDP services
    tcp_portrange = Column(String(255))  # "80" or "80-443" or "80 443 8080"
    udp_portrange = Column(String(255))
    sctp_portrange = Column(String(255))
    
    # For ICMP
    icmptype = Column(Integer)
    icmpcode = Column(Integer)
    
    # For IP protocol
    protocol_number = Column(Integer)  # IP protocol number
    
    # For groups
    is_group = Column(Boolean, default=False)
    members = Column(JSONB)  # List of member service names
    
    # Additional settings
    visibility = Column(String(20), default='enable')
    comments = Column(String(500))
    
    # Full raw config
    config_data = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = db.relationship('Equipo', backref=db.backref('service_objects', lazy='dynamic', cascade='all, delete-orphan'))
    vdom = db.relationship('VDOM', backref=db.backref('service_objects', lazy='dynamic'))
    
    __table_args__ = (
        UniqueConstraint('device_id', 'vdom_id', 'name', name='uq_device_vdom_service'),
    )
    
    def __repr__(self):
        return f"<ServiceObject {self.name}>"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'device_id': str(self.device_id),
            'vdom_id': str(self.vdom_id) if self.vdom_id else None,
            'name': self.name,
            'category': self.category,
            'protocol': self.protocol,
            'tcp_portrange': self.tcp_portrange,
            'udp_portrange': self.udp_portrange,
            'is_group': self.is_group,
            'members': self.members
        }
    
    @property
    def display_ports(self):
        """Human-readable port display"""
        parts = []
        if self.tcp_portrange:
            parts.append(f"TCP/{self.tcp_portrange}")
        if self.udp_portrange:
            parts.append(f"UDP/{self.udp_portrange}")
        if self.icmptype is not None:
            parts.append(f"ICMP type {self.icmptype}")
        if self.is_group:
            parts.append(f"Group ({len(self.members or [])} services)")
        return ", ".join(parts) if parts else self.protocol or "ANY"
