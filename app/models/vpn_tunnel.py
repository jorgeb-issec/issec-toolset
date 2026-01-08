"""
VPN Tunnels Model - IPSec and SSL-VPN tunnel tracking
IS Security Toolset 1.3.0
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.extensions.db import db


class VPNTunnel(db.Model):
    """
    Represents a VPN tunnel configuration (IPSec Phase1/Phase2 or SSL-VPN)
    """
    __tablename__ = 'vpn_tunnels'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey('equipos.id'), nullable=False, index=True)
    vdom_id = Column(UUID(as_uuid=True), ForeignKey('vdoms.id'), nullable=True, index=True)
    
    # Tunnel identification
    name = Column(String(255), nullable=False, index=True)
    type = Column(String(50))  # ipsec, ssl-vpn, pptp, l2tp
    
    # Phase1 (IKE) configuration - for IPSec
    remote_gateway = Column(String(255))  # Remote gateway IP or FQDN
    local_gateway = Column(String(50))  # Local gateway selection
    interface = Column(String(100))  # Linked interface name
    interface_id = Column(UUID(as_uuid=True), ForeignKey('interfaces.id'), nullable=True)
    
    # Authentication
    authmethod = Column(String(50))  # psk, signature, psk-radius
    psk_key = Column(String(255))  # Pre-shared key (may be masked)
    
    # IKE settings
    ike_version = Column(Integer)  # 1 or 2
    mode = Column(String(20))  # main, aggressive (for IKEv1)
    
    # Encryption proposals
    proposals = Column(JSONB)  # List of encryption/auth algorithms
    
    # DPD settings
    dpd = Column(String(20))  # on-idle, on-demand, disable
    dpd_retrycount = Column(Integer)
    dpd_retryinterval = Column(Integer)
    
    # NAT traversal
    nattraversal = Column(String(20))  # enable, disable, forced
    
    # Phase2 settings (stored as JSONB for flexibility)
    phase2_settings = Column(JSONB)  # [{name, local_subnet, remote_subnet, proposal, ...}]
    
    # Status (may be updated dynamically)
    status = Column(String(20))  # up, down, negotiating
    
    # Full raw config
    config_data = Column(JSONB)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    
    # Relationships
    device = db.relationship('Equipo', backref=db.backref('vpn_tunnels', lazy='dynamic', cascade='all, delete-orphan'))
    vdom = db.relationship('VDOM', backref=db.backref('vpn_tunnels', lazy='dynamic'))
    bound_interface = db.relationship('Interface', backref='vpn_tunnels')
    
    __table_args__ = (
        UniqueConstraint('device_id', 'name', name='uq_device_vpn'),
    )
    
    def __repr__(self):
        return f"<VPNTunnel {self.name} ({self.type})>"
    
    def to_dict(self):
        return {
            'id': str(self.id),
            'device_id': str(self.device_id),
            'vdom_id': str(self.vdom_id) if self.vdom_id else None,
            'name': self.name,
            'type': self.type,
            'remote_gateway': self.remote_gateway,
            'interface': self.interface,
            'ike_version': self.ike_version,
            'authmethod': self.authmethod,
            'status': self.status,
            'phase2_count': len(self.phase2_settings) if self.phase2_settings else 0
        }
