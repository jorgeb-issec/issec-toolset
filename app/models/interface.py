"""
Interface Model - Normalized interface storage from FortiGate config
IS Security Toolset 1.3.0
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, Text, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db


class Interface(db.Model):
    """
    Represents a network interface on a FortiGate device.
    Normalized from the config_data JSONB in Equipo.
    """
    __tablename__ = 'interfaces'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False, index=True)
    vdom_id = Column(UUID(as_uuid=True), ForeignKey('vdoms.id'), nullable=True, index=True)
    
    # Interface identification
    name = Column(String(100), nullable=False, index=True)
    alias = Column(String(100))
    type = Column(String(50))  # physical, vlan, aggregate, tunnel, loopback, vdom-link
    status = Column(String(20), default='up')  # up, down, admin-down
    
    # Network configuration
    ip_address = Column(String(50))  # CIDR notation: 192.168.1.1/24
    netmask = Column(String(50))
    gateway = Column(String(50))
    vlan_id = Column(Integer)
    
    # Zone and access
    role = Column(String(50))  # lan, wan, dmz, undefined
    zone = Column(String(100))
    allowaccess = Column(JSONB)  # ["https", "ssh", "ping"] - CRITICAL for security
    
    # Speed/duplex (mostly informational)
    speed = Column(String(50))
    
    # Full raw interface config
    config_data = Column(JSONB)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    device = db.relationship('Equipo', backref=db.backref('interfaces', lazy='dynamic', cascade='all, delete-orphan'))
    vdom = db.relationship('VDOM', backref=db.backref('interfaces', lazy='dynamic'))
    
    __table_args__ = (
        UniqueConstraint('device_id', 'name', name='uq_device_interface'),
    )
    
    def __repr__(self):
        return f"<Interface {self.name} on {self.device_id}>"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'device_id': str(self.device_id),
            'vdom_id': str(self.vdom_id) if self.vdom_id else None,
            'name': self.name,
            'alias': self.alias,
            'type': self.type,
            'status': self.status,
            'ip_address': self.ip_address,
            'netmask': self.netmask,
            'vlan_id': self.vlan_id,
            'role': self.role,
            'zone': self.zone,
            'allowaccess': self.allowaccess
        }


class InterfaceHistory(db.Model):
    """Track interface configuration changes over time"""
    __tablename__ = 'interface_history'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    interface_id = Column(UUID(as_uuid=True), index=True, nullable=False)  # Not FK to allow deleted interfaces
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False)
    
    change_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    change_type = Column(String(20), nullable=False)  # create, modify, delete
    
    # What changed
    field_changed = Column(String(100))  # ip_address, allowaccess, status, etc.
    old_value = Column(JSONB)
    new_value = Column(JSONB)
    
    # Full interface config at this point
    snapshot = Column(JSONB)
    
    def __repr__(self):
        return f"<InterfaceHistory {self.interface_id} - {self.change_type}>"
