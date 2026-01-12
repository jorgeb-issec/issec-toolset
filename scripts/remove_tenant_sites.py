
import os
import sys
from sqlalchemy import create_engine, text

sys.path.append(os.getcwd())
from app import create_app
from app.models.core import Company

def remove_tenant_sites():
    app = create_app()
    with app.app_context():
        tenants = Company.query.all()
        print(f"Found {len(tenants)} tenants to process.")
        
        for tenant in tenants:
            if not tenant.db_uri:
                continue
                
            print(f"Processing tenant: {tenant.name}...")
            
            try:
                engine = create_engine(tenant.db_uri)
                with engine.begin() as conn:
                    # 1. Drop Constraint if exists
                    # Need to find constraint name usually, but if standard naming:
                    # 'equipos_site_id_fkey'. Or we specifically check.
                    
                    # Check for FK constraint name on equipos.site_id
                    res = conn.execute(text("""
                        SELECT conname
                        FROM pg_constraint
                        WHERE conrelid = 'equipos'::regclass
                        AND confrelid = 'sites'::regclass
                    """)).fetchall()
                    
                    for row in res:
                        fk_name = row[0]
                        print(f"   Dropping FK constraint: {fk_name}...")
                        conn.execute(text(f"ALTER TABLE equipos DROP CONSTRAINT {fk_name}"))

                    # 2. Check if sites table exists and drop it
                    table_exists = conn.execute(text("SELECT to_regclass('public.sites')")).scalar()
                    if table_exists:
                        print("   Dropping table 'sites'...")
                        conn.execute(text("DROP TABLE sites"))
                    else:
                        print("   Table 'sites' already gone.")

                    print("   ✅ Cleanup complete.")
                    
            except Exception as e:
                print(f"   ❌ Error: {e}")

if __name__ == '__main__':
    remove_tenant_sites()
