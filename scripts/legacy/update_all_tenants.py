#!/usr/bin/env python3
"""
Script to update policy_history table in ALL tenant databases
"""
from app import create_app
from app.extensions.db import db
from app.models.core import Company
from sqlalchemy import create_engine, text, inspect

def update_tenant_databases():
    """Update policy_history table in all tenant databases"""
    app = create_app()
    
    with app.app_context():
        print("🔄 Updating policy_history table in all tenant databases")
        print("=" * 70)
        
        # Get all companies (tenants)
        companies = Company.query.all()
        
        if not companies:
            print("⚠️  No tenants found. Creating tables in main database only.")
            companies = []
        
        print(f"\n📊 Found {len(companies)} tenant(s)")
        
        for company in companies:
            print(f"\n{'='*70}")
            print(f"🏢 Processing tenant: {company.name}")
            print(f"   Database: {company.db_uri}")
            print("-" * 70)
            
            try:
                # Create engine for this tenant
                tenant_engine = create_engine(company.db_uri)
                
                # Check if policy_history table exists
                inspector = inspect(tenant_engine)
                tables = inspector.get_table_names()
                
                if 'policy_history' not in tables:
                    print("   ⚠️  Table policy_history does not exist. Creating...")
                    # Import all models to ensure metadata is complete
                    from app.models.history import PolicyHistory
                    from app.models.policy import Policy
                    from app.models.equipo import Equipo
                    from app.models.site import Site
                    from app.models.vdom import VDOM
                    
                    # Create all tables
                    db.metadata.create_all(tenant_engine)
                    print("   ✅ All tables created")
                else:
                    # Check if vdom column exists
                    columns = [col['name'] for col in inspector.get_columns('policy_history')]
                    
                    if 'vdom' in columns and 'import_session_id' in columns:
                        print("   ✅ Table already up to date")
                        continue
                    
                    print("   📝 Table exists but needs update")
                    
                    with tenant_engine.connect() as conn:
                        # Add vdom column if missing
                        if 'vdom' not in columns:
                            print("      1️⃣ Adding 'vdom' column...")
                            conn.execute(text("""
                                ALTER TABLE policy_history 
                                ADD COLUMN vdom VARCHAR(50)
                            """))
                            conn.commit()
                            
                            print("      2️⃣ Setting default values...")
                            conn.execute(text("""
                                UPDATE policy_history 
                                SET vdom = 'root' 
                                WHERE vdom IS NULL
                            """))
                            conn.commit()
                            
                            print("      3️⃣ Making column NOT NULL...")
                            conn.execute(text("""
                                ALTER TABLE policy_history 
                                ALTER COLUMN vdom SET NOT NULL
                            """))
                            conn.commit()
                            
                            print("      4️⃣ Creating index...")
                            conn.execute(text("""
                                CREATE INDEX IF NOT EXISTS ix_policy_history_vdom 
                                ON policy_history(vdom)
                            """))
                            conn.commit()
                            print("      ✅ Column 'vdom' added")
                        
                        # Add import_session_id column if missing
                        if 'import_session_id' not in columns:
                            print("      5️⃣ Adding 'import_session_id' column...")
                            conn.execute(text("""
                                ALTER TABLE policy_history 
                                ADD COLUMN import_session_id UUID
                            """))
                            conn.commit()
                            
                            print("      6️⃣ Creating index...")
                            conn.execute(text("""
                                CREATE INDEX IF NOT EXISTS ix_policy_history_import_session_id 
                                ON policy_history(import_session_id)
                            """))
                            conn.commit()
                            print("      ✅ Column 'import_session_id' added")
                
                # Verify final schema
                inspector = inspect(tenant_engine)
                columns = inspector.get_columns('policy_history')
                print(f"\n   📋 Final schema ({len(columns)} columns):")
                for col in columns:
                    nullable = "NULL" if col['nullable'] else "NOT NULL"
                    print(f"      • {col['name']:25s} {str(col['type']):20s} {nullable}")
                
                print(f"\n   ✅ Tenant '{company.name}' updated successfully!")
                
                # Cleanup
                tenant_engine.dispose()
                
            except Exception as e:
                print(f"\n   ❌ Error updating tenant '{company.name}': {str(e)}")
                import traceback
                traceback.print_exc()
                continue
        
        print("\n" + "=" * 70)
        print("✅ Migration completed for all tenants!")
        print("=" * 70)

if __name__ == '__main__':
    update_tenant_databases()
