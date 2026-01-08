"""
Log Entry Model for Log Analyzer
Stores parsed logs from FortiAnalyzer for security analysis
"""
from app.extensions.db import db
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from datetime import datetime


class LogEntry(db.Model):
    """
    Represents a single log entry from FortiGate/FortiAnalyzer
    
    Fields are based on FortiGate traffic log format:
    - type: traffic, event, ips, dns, etc.
    - subtype: forward, local, etc.
    """
    __tablename__ = 'log_entries'
    
    # Primary Key
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign Keys
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey('equipos.id'), index=True)
    
    # v1.3.0 - VDOM FK for proper relationship queries
    vdom_id = db.Column(UUID(as_uuid=True), db.ForeignKey('vdoms.id'), nullable=True, index=True)
    
    # Log Identification
    log_id = db.Column(db.String(50))  # From logid field
    log_type = db.Column(db.String(50), index=True)  # traffic, event, ips, etc.
    subtype = db.Column(db.String(50), index=True)  # forward, local, etc.
    level = db.Column(db.String(20))  # notice, warning, error, etc.
    
    # Timestamps
    timestamp = db.Column(db.DateTime, index=True)  # From date + time
    itime = db.Column(db.BigInteger)  # Original Unix timestamp
    eventtime = db.Column(db.BigInteger)  # Nanosecond precision timestamp
    
    # Device Info
    devid = db.Column(db.String(50), index=True)  # FortiGate device ID
    devname = db.Column(db.String(100))
    vdom = db.Column(db.String(50), index=True)  # vd field
    
    # Source Info
    src_intf = db.Column(db.String(100))  # srcintf
    src_intf_id = db.Column(UUID(as_uuid=True), db.ForeignKey('interfaces.id'), nullable=True, index=True)  # v1.3.0
    src_intf_role = db.Column(db.String(50))  # srcintfrole
    src_ip = db.Column(db.String(50), index=True)
    src_port = db.Column(db.Integer)
    src_country = db.Column(db.String(100))
    src_city = db.Column(db.String(100))
    src_mac = db.Column(db.String(20))
    
    # Destination Info
    dst_intf = db.Column(db.String(100))  # dstintf
    dst_intf_id = db.Column(UUID(as_uuid=True), db.ForeignKey('interfaces.id'), nullable=True, index=True)  # v1.3.0
    dst_intf_role = db.Column(db.String(50))  # dstintfrole
    dst_ip = db.Column(db.String(50), index=True)
    dst_port = db.Column(db.Integer)
    dst_country = db.Column(db.String(100))
    dst_city = db.Column(db.String(100))
    
    # Policy Info
    policy_id = db.Column(db.Integer, index=True)
    policy_uuid = db.Column(UUID(as_uuid=True), db.ForeignKey('policies.uuid'), nullable=True)  # Link to our Policy model
    policy_type = db.Column(db.String(50))  # policytype
    
    # Traffic Info
    action = db.Column(db.String(50), index=True)  # accept, deny, client-rst, etc.
    protocol = db.Column(db.Integer)  # proto field (6=TCP, 17=UDP)
    service = db.Column(db.String(100))  # service field
    app = db.Column(db.String(100))  # app field
    app_cat = db.Column(db.String(100))  # appcat field
    
    # Bytes and Packets
    sent_bytes = db.Column(db.BigInteger)
    rcvd_bytes = db.Column(db.BigInteger)
    sent_pkts = db.Column(db.Integer)
    rcvd_pkts = db.Column(db.Integer)
    duration = db.Column(db.Integer)  # Session duration in seconds
    
    # Session Info
    session_id = db.Column(db.BigInteger)
    nat_type = db.Column(db.String(50))  # trandisp
    
    # Threat Info (for IPS/AV logs)
    threats = db.Column(JSONB)  # threats array
    threat_level = db.Column(db.String(20))
    
    # Raw Data
    raw_data = db.Column(JSONB)  # Complete original log entry
    
    # Import Tracking
    import_session_id = db.Column(UUID(as_uuid=True), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    device = db.relationship('Equipo', backref='log_entries')
    vdom_ref = db.relationship('VDOM', backref=db.backref('log_entries', lazy='dynamic'))
    src_interface = db.relationship('Interface', foreign_keys=[src_intf_id], backref='logs_as_src')
    dst_interface = db.relationship('Interface', foreign_keys=[dst_intf_id], backref='logs_as_dst')
    
    def __repr__(self):
        return f'<LogEntry {self.log_type}/{self.action} {self.src_ip}→{self.dst_ip}>'


class LogImportSession(db.Model):
    """
    Tracks log import sessions for batch analysis
    """
    __tablename__ = 'log_import_sessions'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = db.Column(UUID(as_uuid=True), db.ForeignKey('equipos.id'))
    
    filename = db.Column(db.String(255))
    imported_at = db.Column(db.DateTime, default=datetime.utcnow)
    log_count = db.Column(db.Integer, default=0)
    
    # Date range of imported logs
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    
    # Stats
    stats = db.Column(JSONB)  # Counts by type, action, etc.
    
    device = db.relationship('Equipo', backref='log_import_sessions')


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
    
    # Evidence
    evidence = db.Column(JSONB)  # Log samples, stats, etc.
    affected_count = db.Column(db.Integer)  # Number of logs/policies affected
    
    # Status
    status = db.Column(db.String(20), default='open')  # open, acknowledged, resolved, ignored
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.String(100))
    
    device = db.relationship('Equipo', backref='security_recommendations')
