"""
Security Alerts Model - Track security exposures and allowed access risks
IS Security Toolset 1.3.0
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db


class AllowedAccessAlert(db.Model):
    """
    Tracks risky allowed access configurations on interfaces.
    For example: SSH enabled on WAN interface, HTTP on DMZ, etc.
    """
    __tablename__ = 'allowed_access_alerts'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    interface_id = Column(UUID(as_uuid=True), ForeignKey('interfaces.id', ondelete='CASCADE'), nullable=False, index=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False, index=True)
    vdom_id = Column(UUID(as_uuid=True), ForeignKey('vdoms.id'), nullable=True, index=True)
    
    # Alert details
    service = Column(String(50), nullable=False)  # ssh, telnet, http, https, ping, snmp
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    
    # Why this is flagged
    reason = Column(Text)
    
    # Interface context
    interface_name = Column(String(100))
    interface_role = Column(String(50))  # wan, lan, dmz
    interface_zone = Column(String(100))
    
    # Status tracking
    status = Column(String(20), default='open')  # open, acknowledged, mitigated, false_positive
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    resolved_by = Column(String(100))
    
    # Relationships
    interface = db.relationship('Interface', backref=db.backref('access_alerts', lazy='dynamic', cascade='all, delete-orphan'))
    device = db.relationship('Equipo', backref=db.backref('access_alerts', lazy='dynamic'))
    
    def __repr__(self):
        return f"<AllowedAccessAlert {self.service} on {self.interface_name} ({self.severity})>"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'interface_id': str(self.interface_id),
            'interface_name': self.interface_name,
            'service': self.service,
            'severity': self.severity,
            'reason': self.reason,
            'interface_role': self.interface_role,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ServerExposure(db.Model):
    """
    Tracks internal servers potentially exposed to external attacks.
    Based on policy analysis and log data.
    """
    __tablename__ = 'server_exposures'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False, index=True)
    vdom_id = Column(UUID(as_uuid=True), ForeignKey('vdoms.id'), nullable=True, index=True)
    
    # Server identification
    server_ip = Column(String(50), nullable=False, index=True)
    server_name = Column(String(255))  # Hostname or description
    
    # Internal network
    internal_zone = Column(String(100))  # LAN, DMZ, etc.
    
    # Exposure details
    exposed_ports = Column(JSONB)  # [{"port": 80, "protocol": "tcp", "service": "HTTP"}]
    exposed_via_policies = Column(JSONB)  # [{"policy_id": 123, "vdom": "root", "name": "..."}]
    
    # Risk assessment
    severity = Column(String(20))  # critical, high, medium, low
    exposure_type = Column(String(50))  # direct_internet, nat, vpn_only, dmz_isolated
    
    # Evidence from logs
    log_count = Column(Integer, default=0)  # Number of external access logs
    external_ips_count = Column(Integer, default=0)  # Unique external IPs accessing
    last_access = Column(DateTime)
    first_seen = Column(DateTime)
    
    # Status
    status = Column(String(20), default='active')  # active, acknowledged, mitigated, decommissioned
    
    # Additional context
    notes = Column(Text)
    evidence = Column(JSONB)  # Sample logs, policy details, etc.
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    device = db.relationship('Equipo', backref=db.backref('server_exposures', lazy='dynamic'))
    vdom = db.relationship('VDOM', backref=db.backref('server_exposures', lazy='dynamic'))
    
    def __repr__(self):
        return f"<ServerExposure {self.server_ip} ({self.severity})>"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'server_ip': self.server_ip,
            'server_name': self.server_name,
            'exposed_ports': self.exposed_ports,
            'severity': self.severity,
            'exposure_type': self.exposure_type,
            'log_count': self.log_count,
            'status': self.status
        }
