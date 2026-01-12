#!/usr/bin/env python
"""
Script to run migrations on all tenant databases
IS Security Toolset v1.3.0
"""
import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.extensions.db import db
from app.models.core import Company
from sqlalchemy import create_engine, text
from alembic.config import Config
from alembic import command

def migrate_all_tenants():
    """Run alembic upgrade on all tenant databases."""
    app = create_app()
    
    with app.app_context():
        # Get all companies with their db_uri
        companies = Company.query.all()
        
        print(f"Found {len(companies)} tenant databases to migrate")
        print("-" * 50)
        
        for company in companies:
            print(f"\n📦 Migrating: {company.name}")
            print(f"   Database: {company.db_uri.split('/')[-1]}")
            
            try:
                # Create engine for tenant DB
                engine = create_engine(company.db_uri)
                
                # Run raw SQL to add new columns (simpler than alembic for tenant DBs)
                with engine.connect() as conn:
                    # Check if vdom_id column already exists
                    result = conn.execute(text("""
                        SELECT column_name FROM information_schema.columns 
                        WHERE table_name = 'policies' AND column_name = 'vdom_id'
                    """))
                    
                    if result.fetchone():
                        print("   ✅ Already migrated (vdom_id exists)")
                        conn.commit()
                        continue
                    
                    # Add vdom_id to policies
                    print("   Adding vdom_id to policies...")
                    conn.execute(text("ALTER TABLE policies ADD COLUMN IF NOT EXISTS vdom_id UUID"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_policies_vdom_id ON policies(vdom_id)"))
                    
                    # Add columns to log_entries if table exists
                    result = conn.execute(text("""
                        SELECT table_name FROM information_schema.tables 
                        WHERE table_name = 'log_entries'
                    """))
                    if result.fetchone():
                        print("   Adding columns to log_entries...")
                        conn.execute(text("ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS vdom_id UUID"))
                        conn.execute(text("ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS src_intf_id UUID"))
                        conn.execute(text("ALTER TABLE log_entries ADD COLUMN IF NOT EXISTS dst_intf_id UUID"))
                        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_log_entries_vdom_id ON log_entries(vdom_id)"))
                        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_log_entries_src_intf_id ON log_entries(src_intf_id)"))
                        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_log_entries_dst_intf_id ON log_entries(dst_intf_id)"))
                    
                    # Add vdom_id to policy_history if table exists
                    result = conn.execute(text("""
                        SELECT table_name FROM information_schema.tables 
                        WHERE table_name = 'policy_history'
                    """))
                    if result.fetchone():
                        print("   Adding vdom_id to policy_history...")
                        conn.execute(text("ALTER TABLE policy_history ADD COLUMN IF NOT EXISTS vdom_id UUID"))
                        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_policy_history_vdom_id ON policy_history(vdom_id)"))

                    # v1.3.1 - Add topology_data to sites
                    # Only if 'sites' table is in tenant DB (user feedback implies it is)
                    # Use simpler check or just try
                    try:
                        conn.execute(text("SELECT 1 FROM sites LIMIT 1"))
                        print("   Adding topology_data to sites...")
                        conn.execute(text("ALTER TABLE sites ADD COLUMN IF NOT EXISTS topology_data JSONB"))
                    except Exception as e:
                        print(f"   Note: 'sites' table not found or error: {e}")
                    
                    conn.commit()
                    print("   ✅ Migration complete!")
                    
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        print("\n" + "=" * 50)
        print("✅ All tenant migrations complete!")


if __name__ == '__main__':
    migrate_all_tenants()
