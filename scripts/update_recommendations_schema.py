
import os
import sys
from sqlalchemy import create_engine, text

sys.path.append(os.getcwd())
from app import create_app
from app.models.core import Company

def update_schema():
    app = create_app()
    with app.app_context():
        tenants = Company.query.all()
        print(f"Found {len(tenants)} tenants.")
        
        for tenant in tenants:
            if not tenant.db_uri:
                continue
            
            print(f"Updating tenant: {tenant.name}...")
            try:
                engine = create_engine(tenant.db_uri)
                with engine.begin() as conn:
                    # Check table
                    if conn.execute(text("SELECT to_regclass('public.security_recommendations')")).scalar():
                        print("   Table found. Checking columns...")
                        
                        # Add cli_remediation
                        try:
                            conn.execute(text("ALTER TABLE security_recommendations ADD COLUMN IF NOT EXISTS cli_remediation TEXT"))
                            print("   Added cli_remediation.")
                        except Exception as e:
                            print(f"   Error adding cli_remediation: {e}")

                        # Add suggested_policy
                        try:
                            conn.execute(text("ALTER TABLE security_recommendations ADD COLUMN IF NOT EXISTS suggested_policy JSONB"))
                            print("   Added suggested_policy.")
                        except Exception as e:
                            print(f"   Error adding suggested_policy: {e}")
                            
                    else:
                        print("   Table security_recommendations not found!")
                        
            except Exception as e:
                print(f"   ❌ Error: {e}")

if __name__ == '__main__':
    update_schema()
