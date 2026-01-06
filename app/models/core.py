import uuid
from sqlalchemy.dialects.postgresql import UUID
from app.extensions.db import db

class Company(db.Model):
    __tablename__ = 'companies'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(100), nullable=False, unique=True)
    db_uri = db.Column(db.String(255), nullable=False) # Connection string for the tenant DB
    is_active = db.Column(db.Boolean, default=True)
    products = db.Column(db.JSON, default=list) # List of enabled products, e.g. ["policy_explorer"]
    logo = db.Column(db.String(255), nullable=True) # Filename of the uploaded logo
    gemini_api_key = db.Column(db.String(255), nullable=True) # Encrypted or plain API key for AI features

    # Relationship to roles/users
    user_roles = db.relationship('UserCompanyRole', backref='company', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Company {self.name}>"

class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(50), nullable=False, unique=True) 
    description = db.Column(db.String(200))
    permissions = db.Column(db.JSON, default=dict) 
    # e.g., {"manage_users": True, "create_companies": False}

    def __repr__(self):
        return f"<Role {self.name}>"

class UserCompanyRole(db.Model):
    __tablename__ = 'user_company_roles'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    company_id = db.Column(UUID(as_uuid=True), db.ForeignKey('companies.id'), nullable=True) # Null for Global Roles
    role_id = db.Column(UUID(as_uuid=True), db.ForeignKey('roles.id'), nullable=False)

    role = db.relationship('Role')
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'company_id', name='uq_user_company_role'),
    )
    # Note: In standard SQL, (user_id, NULL) is not unique. 
    # For global roles, we might strictly enforce via application logic or conditional index if needed.
    # For now, application logic will prevent duplicate global assignments.
