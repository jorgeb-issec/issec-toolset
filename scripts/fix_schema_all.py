#!/usr/bin/env python3
import os
import sys
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Path setup
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv()

def fix_central_db(db_uri):
    print(f"\n[+] Checking Central DB...")
    engine = create_engine(db_uri)
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        # Site Topology Check
        if 'sites' in tables:
            cols = [c['name'] for c in inspector.get_columns('sites')]
            if 'topology_data' not in cols:
                print("    [!] Missing sites.topology_data. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE sites ADD COLUMN topology_data JSONB"))
                    conn.commit()
                print("    [✓] Added sites.topology_data")
            else:
                print("    [=] sites.topology_data OK")
        
        # Ensure companies table has gemini_api_key (Migration 3)
        if 'companies' in tables:
            cols = [c['name'] for c in inspector.get_columns('companies')]
            if 'gemini_api_key' not in cols:
                 print("    [!] Missing companies.gemini_api_key. Adding...")
                 with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE companies ADD COLUMN gemini_api_key VARCHAR(255)"))
                    conn.commit()
                 print("    [✓] Added companies.gemini_api_key")

    except Exception as e:
        print(f"    [X] Error fixing central DB: {e}")
    finally:
        engine.dispose()

def fix_tenant_db(db_uri, name):
    print(f"\n[+] Checking Tenant DB: {name}")
    engine = create_engine(db_uri)
    try:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        # 1. Ensure vdoms table exists (Prerequisite for FK)
        if 'vdoms' not in tables:
            print("    [!] Missing table 'vdoms'. Creating...")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE vdoms (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        device_id UUID NOT NULL REFERENCES equipos(id) ON DELETE CASCADE,
                        name VARCHAR(100) NOT NULL,
                        comments VARCHAR(255),
                        config_data JSONB,
                        created_at TIMESTAMP DEFAULT NOW()
                    )
                """))
                conn.commit()
            print("    [✓] Created table vdoms")
            
        # 2. Fix policies table
        if 'policies' in tables:
            cols = [c['name'] for c in inspector.get_columns('policies')]
            
            # Status Check
            if 'status' not in cols:
                print("    [!] Missing policies.status. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE policies ADD COLUMN status VARCHAR(20) DEFAULT 'enable'"))
                    conn.commit()
                print("    [✓] Added policies.status")
            
            # VDOM_ID Check
            if 'vdom_id' not in cols:
                print("    [!] Missing policies.vdom_id. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE policies ADD COLUMN vdom_id UUID REFERENCES vdoms(id) ON DELETE SET NULL"))
                    conn.execute(text("CREATE INDEX idx_policies_vdom_id ON policies(vdom_id)"))
                    conn.commit()
                print("    [✓] Added policies.vdom_id")
            else:
                 print("    [=] policies.vdom_id OK")
        
        # 3. Fix Mapping Tables
        # policy_interface_mappings
        if 'policy_interface_mappings' not in tables:
            print("    [!] Missing table 'policy_interface_mappings'. Creating...")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE policy_interface_mappings (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        policy_uuid UUID NOT NULL REFERENCES policies(uuid) ON DELETE CASCADE,
                        interface_id UUID NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
                        direction VARCHAR(10) NOT NULL,
                        CONSTRAINT uq_policy_interface_direction UNIQUE (policy_uuid, interface_id, direction)
                    )
                """))
                conn.execute(text("CREATE INDEX idx_policy_interface_mappings_policy_uuid ON policy_interface_mappings(policy_uuid)"))
                conn.execute(text("CREATE INDEX idx_policy_interface_mappings_interface_id ON policy_interface_mappings(interface_id)"))
                conn.commit()
            print("    [✓] Created table policy_interface_mappings")

        # policy_address_mappings
        if 'policy_address_mappings' not in tables:
            print("    [!] Missing table 'policy_address_mappings'. Creating...")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE policy_address_mappings (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        policy_uuid UUID NOT NULL REFERENCES policies(uuid) ON DELETE CASCADE,
                        address_id UUID NOT NULL REFERENCES address_objects(id) ON DELETE CASCADE,
                        direction VARCHAR(10) NOT NULL,
                        CONSTRAINT uq_policy_address_direction UNIQUE (policy_uuid, address_id, direction)
                    )
                """))
                conn.execute(text("CREATE INDEX idx_policy_address_mappings_policy_uuid ON policy_address_mappings(policy_uuid)"))
                conn.execute(text("CREATE INDEX idx_policy_address_mappings_address_id ON policy_address_mappings(address_id)"))
                conn.commit()
            print("    [✓] Created table policy_address_mappings")

        # policy_service_mappings
        if 'policy_service_mappings' not in tables:
            print("    [!] Missing table 'policy_service_mappings'. Creating...")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE policy_service_mappings (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        policy_uuid UUID NOT NULL REFERENCES policies(uuid) ON DELETE CASCADE,
                        service_id UUID NOT NULL REFERENCES service_objects(id) ON DELETE CASCADE,
                        CONSTRAINT uq_policy_service UNIQUE (policy_uuid, service_id)
                    )
                """))
                conn.execute(text("CREATE INDEX idx_policy_service_mappings_policy_uuid ON policy_service_mappings(policy_uuid)"))
                conn.execute(text("CREATE INDEX idx_policy_service_mappings_service_id ON policy_service_mappings(service_id)"))
                conn.commit()
            print("    [✓] Created table policy_service_mappings")

        # 4. Fix Security Recommendations (v1.3.1 columns)
        if 'security_recommendations' in tables:
            sr_cols = [c['name'] for c in inspector.get_columns('security_recommendations')]
            
            if 'cli_remediation' not in sr_cols:
                print("    [!] Missing security_recommendations.cli_remediation. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE security_recommendations ADD COLUMN cli_remediation TEXT"))
                    conn.commit()
                print("    [✓] Added security_recommendations.cli_remediation")

            if 'suggested_policy' not in sr_cols:
                print("    [!] Missing security_recommendations.suggested_policy. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE security_recommendations ADD COLUMN suggested_policy JSONB"))
                    conn.commit()
                print("    [✓] Added security_recommendations.suggested_policy")

    except Exception as e:
        print(f"    [X] Error fixing tenant {name}: {e}")
    finally:
        engine.dispose()

def main():
    print("=== ISSEC Comprehensive Schema Fix ===")
    
    # 1. Fix Central DB
    central_uri = os.environ.get('DATABASE_URL')
    if not central_uri:
        from app.config import Config
        central_uri = Config.SQLALCHEMY_DATABASE_URI
        
    fix_central_db(central_uri)
    
    # 2. Fix Tenant DBs
    # We need to query companies from Central DB to get their URIs
    engine = create_engine(central_uri)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Check if companies table exists
        inspector = inspect(engine)
        if 'companies' not in inspector.get_table_names():
             print("[!] No companies table found. Is this the right DB?")
             return

        result = session.execute(text("SELECT name, db_uri FROM companies"))
        companies = result.fetchall()
        
        for name, uri in companies:
            if uri:
                fix_tenant_db(uri, name)
            else:
                print(f"\n[-] Skipping {name} (No DB URI)")
                
    except Exception as e:
        print(f"\n[X] Fatal Error querying companies: {e}")
    finally:
        session.close()
        engine.dispose()
        
    print("\n=== Fix Complete ===")

if __name__ == '__main__':
    main()
