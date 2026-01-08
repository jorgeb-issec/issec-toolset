"""
Address Objects Model - FortiGate firewall address objects
IS Security Toolset 1.3.0
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db


class AddressObject(db.Model):
    """
    Represents a FortiGate address object used in policies.
    Types: ipmask, iprange, fqdn, geography, group
    """
    __tablename__ = 'address_objects'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False, index=True)
    vdom_id = Column(UUID(as_uuid=True), ForeignKey('vdoms.id'), nullable=True, index=True)
    
    # Address identification
    name = Column(String(255), nullable=False, index=True)
    type = Column(String(50))  # ipmask, iprange, fqdn, geography, group, wildcard
    
    # For ipmask types (most common)
    subnet = Column(String(100))  # 192.168.1.0/24 or 192.168.1.0 255.255.255.0
    
    # For iprange types
    start_ip = Column(String(50))
    end_ip = Column(String(50))
    
    # For FQDN types
    fqdn = Column(String(255))
    
    # For geography types  
    country = Column(String(10))
    
    # For wildcard types
    wildcard = Column(String(100))  # 192.168.1.0 0.0.0.255
    
    # For group types
    members = Column(JSONB)  # List of member address names
    
    # Interface association (optional)
    associated_interface = Column(String(100))
    
    # Comments and metadata
    comments = Column(Text)
    visibility = Column(String(20), default='enable')
    
    # Full raw config
    config_data = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = db.relationship('Equipo', backref=db.backref('address_objects', lazy='dynamic', cascade='all, delete-orphan'))
    vdom = db.relationship('VDOM', backref=db.backref('address_objects', lazy='dynamic'))
    
    __table_args__ = (
        UniqueConstraint('device_id', 'vdom_id', 'name', name='uq_device_vdom_address'),
    )
    
    def __repr__(self):
        return f"<AddressObject {self.name} ({self.type})>"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'device_id': str(self.device_id),
            'vdom_id': str(self.vdom_id) if self.vdom_id else None,
            'name': self.name,
            'type': self.type,
            'subnet': self.subnet,
            'fqdn': self.fqdn,
            'country': self.country,
            'members': self.members,
            'comments': self.comments
        }
    
    @property
    def display_value(self):
        """Human-readable value based on type"""
        if self.type == 'ipmask':
            return self.subnet
        elif self.type == 'iprange':
            return f"{self.start_ip}-{self.end_ip}"
        elif self.type == 'fqdn':
            return self.fqdn
        elif self.type == 'geography':
            return self.country
        elif self.type == 'group':
            return f"Group ({len(self.members or [])} members)"
        else:
            return self.name
