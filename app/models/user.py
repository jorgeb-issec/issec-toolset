import uuid
from sqlalchemy.dialects.postgresql import UUID
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions.db import db
from app.extensions.login import login_manager

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    position = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(256))
    profile_pic = db.Column(db.String(255), nullable=True) # Filename of the uploaded profile picture

    # Relationship to companies and roles
    company_roles = db.relationship('UserCompanyRole', backref='user', lazy='dynamic', cascade="all, delete-orphan")

    
    def has_permission(self, permission_name, company_id=None):
        """
        Check if user has a permission.
        - permission_name: e.g. 'manage_users'
        - company_id: Context (UUID string or object). If None, checks for any role having the permission (scoped or global).
                      If provided, checks if the user has this permission specifically for this company OR globally.
        """
        # 1. Check Global Roles (company_id IS NULL)
        global_assignments = self.company_roles.filter_by(company_id=None).all()
        for assignment in global_assignments:
            if assignment.role.permissions.get(permission_name):
                return True
                
        # 2. Check Company Specific Role
        if company_id:
            # Normalize UUID
            if not isinstance(company_id, uuid.UUID):
                 try:
                     company_id = uuid.UUID(str(company_id))
                 except:
                     pass
            
            assignment = self.company_roles.filter_by(company_id=company_id).first()
            if assignment and assignment.role.permissions.get(permission_name):
                return True
                
        return False
        
    def get_global_role(self):
        """Return the first global role assignment if exists"""
        assign = self.company_roles.filter_by(company_id=None).first()
        return assign.role if assign else None

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(uuid.UUID(user_id))