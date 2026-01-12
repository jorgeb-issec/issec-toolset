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
        
        # 0. Ensure ALL tables exist (Auto-creation)
        # We need to bind the app metadata to this engine to create missing tables
        from app.extensions.db import db
        # Import all models to ensure they are registered in metadata
        from app.models.interface import Interface
        from app.models.policy import Policy
        from app.models.vdom import VDOM
        from app.models.address_object import AddressObject
        from app.models.service_object import ServiceObject
        from app.models.policy_mappings import PolicyInterfaceMapping, PolicyAddressMapping, PolicyServiceMapping
        from app.models.security_recommendation import SecurityRecommendation
        from app.models.log_entry import LogEntry

        print("    [+] verifying/creating all tables via SQLAlchemy metadata...")
        db.metadata.create_all(engine)
        
        # Refresh inspector after creation
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        # 1. Ensure vdoms table exists (Prerequisite for FK in manual SQL)
        if 'vdoms' not in tables:
            print("    [!] Missing table 'vdoms'. Creating manually...")
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
            
        # 2. Fix policies table columns
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
        
        # 3. Security Recommendations (v1.3.1 columns)
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

        # 4. Fix Log Entries (v1.3.0 columns)
        if 'log_entries' in tables:
            le_cols = [c['name'] for c in inspector.get_columns('log_entries')]
            
            # vdom_id
            if 'vdom_id' not in le_cols:
                print("    [!] Missing log_entries.vdom_id. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE log_entries ADD COLUMN vdom_id UUID REFERENCES vdoms(id) ON DELETE SET NULL"))
                    conn.execute(text("CREATE INDEX idx_log_entries_vdom_id ON log_entries(vdom_id)"))
                    conn.commit()
                print("    [✓] Added log_entries.vdom_id")

            # policy_uuid
            if 'policy_uuid' not in le_cols:
                print("    [!] Missing log_entries.policy_uuid. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE log_entries ADD COLUMN policy_uuid UUID REFERENCES policies(uuid) ON DELETE SET NULL"))
                    conn.execute(text("CREATE INDEX idx_log_entries_policy_uuid ON log_entries(policy_uuid)"))
                    conn.commit()
                print("    [✓] Added log_entries.policy_uuid")

            # src_intf_id
            if 'src_intf_id' not in le_cols:
                print("    [!] Missing log_entries.src_intf_id. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE log_entries ADD COLUMN src_intf_id UUID REFERENCES interfaces(id) ON DELETE SET NULL"))
                    conn.execute(text("CREATE INDEX idx_log_entries_src_intf_id ON log_entries(src_intf_id)"))
                    conn.commit()
                print("    [✓] Added log_entries.src_intf_id")

            # dst_intf_id
            if 'dst_intf_id' not in le_cols:
                print("    [!] Missing log_entries.dst_intf_id. Adding...")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE log_entries ADD COLUMN dst_intf_id UUID REFERENCES interfaces(id) ON DELETE SET NULL"))
                    conn.execute(text("CREATE INDEX idx_log_entries_dst_intf_id ON log_entries(dst_intf_id)"))
                    conn.commit()
                print("    [✓] Added log_entries.dst_intf_id")

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
