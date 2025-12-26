#!/usr/bin/env python3
"""
Script to create all database tables including policy_history
"""
import sys
import os

# Add parent directory to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions.db import db

# Import all models to ensure they're registered
from app.models.core import Role, UserCompanyRole, Company
from app.models.user import User
from app.models.site import Site
from app.models.equipo import Equipo
from app.models.vdom import VDOM
from app.models.policy import Policy
from app.models.history import PolicyHistory

def create_all_tables():
    """Create all database tables"""
    app = create_app()
    
    with app.app_context():
        print("🔄 Creating all database tables...")
        print("=" * 60)
        
        try:
            # Create all tables
            db.create_all()
            
            print("✅ All tables created successfully!")
            print("\n📋 Tables created:")
            
            # List all tables
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            for table in sorted(tables):
                print(f"   ✓ {table}")
            
            print("\n" + "=" * 60)
            print("✅ Database schema is up to date!")
            
        except Exception as e:
            print(f"\n❌ Error creating tables: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    return True

if __name__ == '__main__':
    success = create_all_tables()
    exit(0 if success else 1)
