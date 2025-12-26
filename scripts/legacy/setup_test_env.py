#!/usr/bin/env python3
"""
Reset Database Script for ISSEC Toolset
- Drops and recreates all tables in Postgres
- Creates admin user and roles
- Does NOT create any companies (admin can create from UI)
"""
import sys
import os

sys.path.append(os.getcwd())

from app import create_app
from app.extensions.db import db
from app.models.core import Company, Role, UserCompanyRole
from app.models.user import User
from app.models.equipo import Equipo
from app.models.site import Site
from app.models.policy import Policy
from app.models.vdom import VDOM
from app.models.history import PolicyHistory

app = create_app()

def setup_database():
    with app.app_context():
        print("--- Resetting Database (Postgres) ---")
        print("⚠️  WARNING: This will DROP ALL TABLES and recreate them.")
        
        db.drop_all()
        db.create_all()
        print("✓ Tables created")
        
        print("--- Creating Roles ---")
        admin_role = Role(name='Admin')
        analyst_role = Role(name='Analyst')
        db.session.add_all([admin_role, analyst_role])
        db.session.commit()
        print("✓ Roles created: Admin, Analyst")
        
        print("--- Creating Admin User ---")
        u_admin = User(username='admin', email='admin@issec.com')
        u_admin.set_password('admin123')
        db.session.add(u_admin)
        db.session.commit()
        print("✓ Admin user created")
        
        # Give admin a global role (company_id=None means global access)
        global_admin_assignment = UserCompanyRole(
            user_id=u_admin.id, 
            company_id=None,  # Global role
            role_id=admin_role.id
        )
        db.session.add(global_admin_assignment)
        db.session.commit()
        print("✓ Global admin role assigned")
        
        print("")
        print("=" * 50)
        print("✅ Setup Complete!")
        print("=" * 50)
        print("Login with: admin / admin123")
        print("")
        print("No companies exist yet. Use the Global Dashboard to create one.")
        print("=" * 50)

if __name__ == "__main__":
    setup_database()
