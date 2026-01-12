
import os
import sys
from sqlalchemy import create_engine, text

# Adjust path to import app modules if needed
sys.path.append(os.getcwd())

from app import create_app
from app.models.core import Company

def fix_tenant_sites():
    app = create_app()
    with app.app_context():
        # Get all tenants
        tenants = Company.query.all()
        print(f"Found {len(tenants)} tenants.")
        
        for tenant in tenants:
            if not tenant.db_uri:
                print(f"Skipping tenant {tenant.name} (no db_uri)")
                continue
                
            print(f"Checking tenant: {tenant.name}...")
            
            # Use stored URI directly
            tenant_url = tenant.db_uri
            
            try:
                # Create engine for tenant DB
                tenant_engine = create_engine(tenant_url)
                
                # Check connection and table
                with tenant_engine.connect() as conn:
                    # Check if sites table exists
                    res = conn.execute(text("SELECT to_regclass('public.sites')")).scalar()
                    if res:
                        print(f"   Table 'sites' exists. checking column...")
                        # Check column
                        try:
                            # Try simple select
                            conn.execute(text("SELECT topology_data FROM sites LIMIT 0"))
                            print("   Column 'topology_data' already exists.")
                        except Exception:
                            print("   Column missing! Adding it...")
                            # Transaction might be aborted, need new transaction
                        
                        # Apply ALTER
                        # We use a separate connection/transaction to be sure
                        with tenant_engine.begin() as trans_conn:
                             trans_conn.execute(text("ALTER TABLE sites ADD COLUMN IF NOT EXISTS topology_data JSONB"))
                             print("   ✅ Fixed: Added topology_data column.")

                    else:
                        print("   Target table 'sites' does not exist in this tenant DB (expected behavior if Sites are global).")
                        
            except Exception as e:
                print(f"   ❌ Error processing tenant {tenant.name}: {e}")

if __name__ == "__main__":
    fix_tenant_sites()
