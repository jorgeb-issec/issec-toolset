"""
Policy Mapping Models - Intermediate tables for N:M relationships
IS Security Toolset 1.3.0
"""
import uuid
from sqlalchemy import Column, String, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from app.extensions.db import db


class PolicyInterfaceMapping(db.Model):
    """
    Maps policies to their source/destination interfaces.
    A policy can have multiple interfaces in srcintf/dstintf.
    """
    __tablename__ = 'policy_interface_mappings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_uuid = Column(UUID(as_uuid=True), ForeignKey('policies.uuid', ondelete='CASCADE'), nullable=False, index=True)
    interface_id = Column(UUID(as_uuid=True), ForeignKey('interfaces.id', ondelete='CASCADE'), nullable=False, index=True)
    direction = Column(String(10), nullable=False)  # 'src' or 'dst'
    
    # Relationships
    policy = db.relationship('Policy', backref=db.backref('interface_mappings', lazy='dynamic', cascade='all, delete-orphan'))
    interface = db.relationship('Interface', backref=db.backref('policy_mappings', lazy='dynamic'))
    
    __table_args__ = (
        UniqueConstraint('policy_uuid', 'interface_id', 'direction', 
                        name='uq_policy_interface_direction'),
    )
    
    def __repr__(self):
        return f"<PolicyInterfaceMapping {self.direction}: {self.policy_uuid} -> {self.interface_id}>"


class PolicyAddressMapping(db.Model):
    """
    Maps policies to their source/destination addresses.
    A policy can have multiple address objects in srcaddr/dstaddr.
    """
    __tablename__ = 'policy_address_mappings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_uuid = Column(UUID(as_uuid=True), ForeignKey('policies.uuid', ondelete='CASCADE'), nullable=False, index=True)
    address_id = Column(UUID(as_uuid=True), ForeignKey('address_objects.id', ondelete='CASCADE'), nullable=False, index=True)
    direction = Column(String(10), nullable=False)  # 'src' or 'dst'
    
    # Relationships
    policy = db.relationship('Policy', backref=db.backref('address_mappings', lazy='dynamic', cascade='all, delete-orphan'))
    address = db.relationship('AddressObject', backref=db.backref('policy_mappings', lazy='dynamic'))
    
    __table_args__ = (
        UniqueConstraint('policy_uuid', 'address_id', 'direction',
                        name='uq_policy_address_direction'),
    )
    
    def __repr__(self):
        return f"<PolicyAddressMapping {self.direction}: {self.policy_uuid} -> {self.address_id}>"


class PolicyServiceMapping(db.Model):
    """
    Maps policies to their services.
    A policy can have multiple service objects.
    """
    __tablename__ = 'policy_service_mappings'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_uuid = Column(UUID(as_uuid=True), ForeignKey('policies.uuid', ondelete='CASCADE'), nullable=False, index=True)
    service_id = Column(UUID(as_uuid=True), ForeignKey('service_objects.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Relationships
    policy = db.relationship('Policy', backref=db.backref('service_mappings', lazy='dynamic', cascade='all, delete-orphan'))
    service = db.relationship('ServiceObject', backref=db.backref('policy_mappings', lazy='dynamic'))
    
    __table_args__ = (
        UniqueConstraint('policy_uuid', 'service_id', name='uq_policy_service'),
    )
    
    def __repr__(self):
        return f"<PolicyServiceMapping {self.policy_uuid} -> {self.service_id}>"
