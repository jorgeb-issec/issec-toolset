#!/usr/bin/env python3
"""
Script to apply updates to Tenant Databases
(Indices, missing columns, etc.)
"""
import sys
import os
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Add parent directory to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models.core import Company
from app.services.tenant_service import TenantService

def apply_indices(engine):
    """Apply performance indices to a tenant database"""
    with engine.connect() as conn:
        print("   - Applying indices...")
        
        # Helper to execute raw SQL safely
        def safe_create_index(name, table, columns, desc=False):
            try:
                # Check if index exists
                check_sql = sa.text(f"SELECT 1 FROM pg_indexes WHERE indexname = '{name}'")
                if conn.execute(check_sql).fetchone():
                    return # Exists
                
                print(f"     + Creating {name} on {table}")
                if desc:
                    # columns is list of cols, last one is DESC
                    base_cols = ", ".join(columns[:-1])
                    desc_col = columns[-1]
                    sql = f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {table} ({base_cols}, {desc_col} DESC)"
                else:
                    cols = ", ".join(columns)
                    sql = f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {table} ({cols})"
                
                # Cannot run CONCURRENTLY in transaction block normally, but we are in engine.connect() (autocommit off by default)
                # We need autocommit for concurrent index
                conn.execute(sa.text("COMMIT")) # Commit previous
                conn.execute(sa.text(sql))
            except Exception as e:
                print(f"     ! Error creating {name}: {e}")

        # LOG ENTRIES
        # idx_logentry_device_timestamp
        try:
             # Basic SQL creation (without concurrent to be safe/simple here in script)
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_logentry_device_timestamp ON log_entries (device_id, timestamp DESC)"))
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_logentry_action ON log_entries (action)"))
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_logentry_device_action ON log_entries (device_id, action)"))
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_logentry_vdom ON log_entries (vdom)"))
        except Exception as e:
             print(f"     ! Error log_entries indices: {e}")

        # POLICIES
        try:
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_policy_device_vdom ON policies (device_id, vdom)"))
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_policy_bytes ON policies (bytes_int)"))
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_policy_hits ON policies (hit_count)"))
        except Exception as e:
             print(f"     ! Error policies indices: {e}")

        # RECOMMENDATIONS
        try:
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_recommendation_device_status ON security_recommendations (device_id, status)"))
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_recommendation_severity ON security_recommendations (severity)"))
             conn.execute(sa.text("CREATE INDEX IF NOT EXISTS idx_recommendation_category ON security_recommendations (category)"))
        except Exception as e:
             print(f"     ! Error recommendations indices: {e}")
             
        conn.commit()


def fix_missing_vdom_id(engine):
    """Add vdom_id to policy_history if missing"""
    with engine.connect() as conn:
        print("   - Checking policy_history schema...")
        inspector = sa.inspect(conn)
        
        try:
            columns = [c['name'] for c in inspector.get_columns('policy_history')]
            if 'vdom_id' not in columns:
                print("     + Adding missing vdom_id column to policy_history")
                conn.execute(sa.text("ALTER TABLE policy_history ADD COLUMN vdom_id UUID"))
                conn.execute(sa.text("CREATE INDEX idx_policy_history_vdom_id ON policy_history (vdom_id)"))
                conn.commit()
                # Try adding FK
                try:
                    conn.execute(sa.text("ALTER TABLE policy_history ADD CONSTRAINT fk_policy_history_vdom_id FOREIGN KEY (vdom_id) REFERENCES vdoms(id) ON DELETE SET NULL"))
                    conn.commit()
                except Exception as e:
                    print(f"     ! Warning FK: {e}")
        except Exception as e:
            print(f"     ! Error checking policy_history: {e}")

def ensure_sites_table_and_migrate(engine):
    """
    1. Ensure 'sites' table exists in tenant DB.
    2. Copy global sites to tenant DB to preserve relationships.
    """
    from app.models.site import Site
    from app.extensions.db import db
    
    # 1. Ensure Table Exists
    # We use SQLAlchemy's metadata to create the table if missing
    # Since Site is bound to Main DB metadata, we strictly use the Table object for creation on this engine
    try:
        Site.__table__.create(engine, checkfirst=True)
        print("     + Verified 'sites' table exists")
    except Exception as e:
        print(f"     ! Error ensuring 'sites' table: {e}")
        
    # 2. Migrate Global Sites
    # We fetch all global sites and insert them into the tenant DB if not present
    # This ensures existing 'site_id' FKs in Equipos remain valid
    try:
        global_sites = db.session.query(Site).all()
        if not global_sites:
             print("     . No global sites to migrate")
             return

        with engine.connect() as conn:
            print(f"     + Migrating {len(global_sites)} global sites...")
            for s in global_sites:
                # Raw SQL insert to avoid session conflicts
                # Check existance first
                check = conn.execute(sa.text(f"SELECT 1 FROM sites WHERE id = '{s.id}'")).fetchone()
                if not check:
                    try:
                        sql = sa.text("""
                            INSERT INTO sites (id, nombre, direccion, topology_data)
                            VALUES (:id, :nombre, :direccion, :topology_data)
                        """)
                        conn.execute(sql, {
                            "id": s.id,
                            "nombre": s.nombre,
                            "direccion": s.direccion,
                            "topology_data": s.topology_data if s.topology_data else None # JSONB
                        })
                    except Exception as ex: # Likely duplicate name but different ID?
                         print(f"       ~ Skipped site {s.nombre} (conflict: {ex})")
            conn.commit()
    except Exception as e:
        print(f"     ! Error migrating sites: {e}")

def main():
    app = create_app()
    with app.app_context():
        print("🔍 Scanning tenants...")
        companies = Company.query.all()
        print(f"Found {len(companies)} companies.")
        
        for company in companies:
            print(f"\n🏢 Processing Company: {company.name} ({company.id})")
            print(f"   DB URI: {company.db_uri}")
            
            try:
                engine = TenantService.get_engine(company.id)
                # 0. Ensure Sites & Migrate
                ensure_sites_table_and_migrate(engine)
                # 1. Apply Indices
                apply_indices(engine)
                # 2. Fix Schema
                fix_missing_vdom_id(engine)
                print("   ✅ Complete")
            except Exception as e:
                print(f"   ❌ Failed: {e}")

if __name__ == '__main__':
    main()
